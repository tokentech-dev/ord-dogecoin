use axum::Json;
use {
    self::{
        deserialize_from_str::DeserializeFromStr,
        error::{OptionExt, ServerError, ServerResult},
    },
    axum::{
        body,
        extract::{Extension, Path, Query},
        headers::UserAgent,
        http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
        response::{IntoResponse, Redirect, Response},
        Router,
        routing::get, TypedHeader,
    },
    axum_server::Handle,
    crate::page_config::PageConfig,
    crate::templates::{
        BlockHtml, HomeHtml, InputHtml, InscriptionHtml, InscriptionsHtml, OutputHtml, PageContent,
        PageHtml, PreviewAudioHtml, PreviewImageHtml, PreviewPdfHtml, PreviewTextHtml,
        PreviewUnknownHtml, PreviewVideoHtml, RangeHtml, RareTxt, SatHtml, TransactionHtml,
    },
    rust_embed::RustEmbed,
    rustls_acme::{
        acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
        AcmeConfig,
        axum::AxumAcceptor,
        caches::DirCache,
    },
    std::{cmp::Ordering, str},
    super::*,
    tokio_stream::StreamExt,
    tower_http::{
        compression::CompressionLayer,
        cors::{Any, CorsLayer},
        set_header::SetResponseHeaderLayer,
    },
};

mod error;

enum BlockQuery {
    Height(u64),
    Hash(BlockHash),
}

impl FromStr for BlockQuery {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.len() == 64 {
            BlockQuery::Hash(s.parse()?)
        } else {
            BlockQuery::Height(s.parse()?)
        })
    }
}

enum SpawnConfig {
    Https(AxumAcceptor),
    Http,
    Redirect(String),
}

#[derive(Deserialize)]
struct Search {
    query: String,
}

#[derive(RustEmbed)]
#[folder = "static"]
struct StaticAssets;

struct StaticHtml {
    title: &'static str,
    html: &'static str,
}

impl PageContent for StaticHtml {
    fn title(&self) -> String {
        self.title.into()
    }
}

impl Display for StaticHtml {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(self.html)
    }
}

#[derive(Debug, Parser)]
pub(crate) struct Server {
    #[clap(
    long,
    default_value = "0.0.0.0",
    help = "Listen on <ADDRESS> for incoming requests."
    )]
    address: String,
    #[clap(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
    )]
    acme_domain: Vec<String>,
    #[clap(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]."
    )]
    http_port: Option<u16>,
    #[clap(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]."
    )]
    https_port: Option<u16>,
    #[clap(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
    acme_cache: Option<PathBuf>,
    #[clap(long, help = "Provide ACME contact <ACME_CONTACT>.")]
    acme_contact: Vec<String>,
    #[clap(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
    http: bool,
    #[clap(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
    https: bool,
    #[clap(long, help = "Redirect HTTP traffic to HTTPS.")]
    redirect_http_to_https: bool,
}

impl Server {
    pub(crate) fn run(self, options: Options, index: Arc<Index>, handle: Handle) -> Result {
        Runtime::new()?.block_on(async {
            let clone = index.clone();
            thread::spawn(move || loop {
                if let Err(error) = clone.update() {
                    log::warn!("{error}");
                }
                thread::sleep(Duration::from_millis(5000));
            });

            let config = options.load_config()?;
            let acme_domains = self.acme_domains()?;

            let page_config = Arc::new(PageConfig {
                chain: options.chain(),
                domain: acme_domains.first().cloned(),
            });

            let router = Router::new()
                .route("/api/block-count", get(Self::api_block_count))
                .route("/api/block/:query", get(Self::api_block))
                .route("/input/:block/:transaction/:input", get(Self::input))
                .route("/api/inscription/:inscription_id", get(Self::api_inscription))
                .route("/api/inscriptions", get(Self::api_inscriptions))
                .route("/api/inscriptions/:from", get(Self::api_inscriptions_from))
                .route("/output/:output", get(Self::output))
                .route("/preview/:inscription_id", get(Self::preview))
                .route("/api/sat/:sat", get(Self::api_sat))
                .route("/api/search/:query", get(Self::api_search))
                .route("/api/tx/:txid", get(Self::api_transaction))
                .layer(Extension(index))
                .layer(Extension(page_config))
                .layer(Extension(Arc::new(config)))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("default-src 'self'"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
                ))
                .layer(
                    CorsLayer::new()
                        .allow_methods([http::Method::GET])
                        .allow_origin(Any),
                )
                .layer(CompressionLayer::new());

            match (self.http_port(), self.https_port()) {
                (Some(http_port), None) => {
                    self
                        .spawn(router, handle, http_port, SpawnConfig::Http)?
                        .await??
                }
                (None, Some(https_port)) => {
                    self
                        .spawn(
                            router,
                            handle,
                            https_port,
                            SpawnConfig::Https(self.acceptor(&options)?),
                        )?
                        .await??
                }
                (Some(http_port), Some(https_port)) => {
                    let http_spawn_config = if self.redirect_http_to_https {
                        SpawnConfig::Redirect(if https_port == 443 {
                            format!("https://{}", acme_domains[0])
                        } else {
                            format!("https://{}:{https_port}", acme_domains[0])
                        })
                    } else {
                        SpawnConfig::Http
                    };

                    let (http_result, https_result) = tokio::join!(
            self.spawn(router.clone(), handle.clone(), http_port, http_spawn_config)?,
            self.spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
          );
                    http_result.and(https_result)??;
                }
                (None, None) => unreachable!(),
            }

            Ok(())
        })
    }

    fn spawn(
        &self,
        router: Router,
        handle: Handle,
        port: u16,
        config: SpawnConfig,
    ) -> Result<task::JoinHandle<io::Result<()>>> {
        let addr = (self.address.as_str(), port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("failed to get socket addrs"))?;

        if !integration_test() {
            eprintln!(
                "Listening on {}://{addr}",
                match config {
                    SpawnConfig::Https(_) => "https",
                    _ => "http",
                }
            );
        }

        Ok(tokio::spawn(async move {
            match config {
                SpawnConfig::Https(acceptor) => {
                    axum_server::Server::bind(addr)
                        .handle(handle)
                        .acceptor(acceptor)
                        .serve(router.into_make_service())
                        .await
                }
                SpawnConfig::Redirect(destination) => {
                    axum_server::Server::bind(addr)
                        .handle(handle)
                        .serve(
                            Router::new()
                                .fallback(Self::redirect_http_to_https)
                                .layer(Extension(destination))
                                .into_make_service(),
                        )
                        .await
                }
                SpawnConfig::Http => {
                    axum_server::Server::bind(addr)
                        .handle(handle)
                        .serve(router.into_make_service())
                        .await
                }
            }
        }))
    }

    fn acme_cache(acme_cache: Option<&PathBuf>, options: &Options) -> Result<PathBuf> {
        let acme_cache = if let Some(acme_cache) = acme_cache {
            acme_cache.clone()
        } else {
            options.data_dir()?.join("acme-cache")
        };

        Ok(acme_cache)
    }

    fn acme_domains(&self) -> Result<Vec<String>> {
        if !self.acme_domain.is_empty() {
            Ok(self.acme_domain.clone())
        } else {
            Ok(vec![sys_info::hostname()?])
        }
    }

    fn http_port(&self) -> Option<u16> {
        if self.http || self.http_port.is_some() || (self.https_port.is_none() && !self.https) {
            Some(self.http_port.unwrap_or(80))
        } else {
            None
        }
    }

    fn https_port(&self) -> Option<u16> {
        if self.https || self.https_port.is_some() {
            Some(self.https_port.unwrap_or(443))
        } else {
            None
        }
    }

    fn acceptor(&self, options: &Options) -> Result<AxumAcceptor> {
        let config = AcmeConfig::new(self.acme_domains()?)
            .contact(&self.acme_contact)
            .cache_option(Some(DirCache::new(Self::acme_cache(
                self.acme_cache.as_ref(),
                options,
            )?)))
            .directory(if cfg!(test) {
                LETS_ENCRYPT_STAGING_DIRECTORY
            } else {
                LETS_ENCRYPT_PRODUCTION_DIRECTORY
            });

        let mut state = config.state();

        let acceptor = state.axum_acceptor(Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_cert_resolver(state.resolver()),
        ));

        tokio::spawn(async move {
            while let Some(result) = state.next().await {
                match result {
                    Ok(ok) => log::info!("ACME event: {:?}", ok),
                    Err(err) => log::error!("ACME error: {:?}", err),
                }
            }
        });

        Ok(acceptor)
    }

    fn api_index_height(index: &Index) -> ServerResult<Json<Height>> {
        index.height()?.map(Json).ok_or_not_found(|| "genesis block")
    }
}

#[derive(Serialize)]
struct ApiSatResponse {
    pub sat: Sat,
    pub satpoint: Option<SatPoint>,
    pub blocktime: Blocktime,
    pub inscription: Option<InscriptionId>,
}

impl Server {
    async fn api_sat(
        Extension(index): Extension<Arc<Index>>,
        Path(DeserializeFromStr(sat)): Path<DeserializeFromStr<Sat>>,
    ) -> ServerResult<Json<ApiSatResponse>> {
        Ok(Json(ApiSatResponse {
            sat,
            satpoint: index.rare_sat_satpoint(sat)?,
            blocktime: index.blocktime(sat.height())?,
            inscription: index.get_inscription_id_by_sat(sat)?,
        }))
    }
}


impl Server {
    async fn output(
        Extension(page_config): Extension<Arc<PageConfig>>,
        Extension(index): Extension<Arc<Index>>,
        Path(outpoint): Path<OutPoint>,
    ) -> ServerResult<PageHtml<OutputHtml>> {
        let list = if index.has_sat_index()? {
            index.list(outpoint)?
        } else {
            None
        };

        let output = if outpoint == OutPoint::null() {
            let mut value = 0;

            if let Some(List::Unspent(ranges)) = &list {
                for (start, end) in ranges {
                    value += u64::try_from(end - start).unwrap();
                }
            }

            TxOut {
                value,
                script_pubkey: Script::new(),
            }
        } else {
            index
                .get_transaction(outpoint.txid)?
                .ok_or_not_found(|| format!("output {outpoint}"))?
                .output
                .into_iter()
                .nth(outpoint.vout as usize)
                .ok_or_not_found(|| format!("output {outpoint}"))?
        };

        let inscriptions = index.get_inscriptions_on_output(outpoint)?;

        Ok(
            OutputHtml {
                outpoint,
                inscriptions,
                list,
                chain: page_config.chain,
                output,
            }
                .page(page_config, index.has_sat_index()?),
        )
    }
}

#[derive(Serialize)]
pub struct ApiBlockResponse {
    pub height: u64,
    pub block: Block,
    pub best_height: u64,
    pub has_sat_index: bool,
}

impl Server {
    async fn api_block(
        Extension(index): Extension<Arc<Index>>,
        Path(DeserializeFromStr(query)): Path<DeserializeFromStr<BlockQuery>>,
    ) -> ServerResult<Json<ApiBlockResponse>> {
        let (block, height) = match query {
            BlockQuery::Height(height) => {
                let block = index
                    .get_block_by_height(height)?
                    .ok_or_not_found(|| format!("block {height}"))?;

                (block, height)
            }
            BlockQuery::Hash(hash) => {
                let info = index
                    .block_header_info(hash)?
                    .ok_or_not_found(|| format!("block {hash}"))?;

                let block = index
                    .get_block_by_hash(hash)?
                    .ok_or_not_found(|| format!("block {hash}"))?;

                (block, info.height as u64)
            }
        };

        Ok(Json(ApiBlockResponse {
            height,
            block,
            best_height: index.height()?.ok_or_not_found(|| "genesis block")?.0,
            has_sat_index: index.has_sat_index()?,
        }))
    }
}

#[derive(Serialize)]
pub struct ApiTransactionResponse {
    pub transaction: Transaction,
    pub block_hash: Option<BlockHash>,
    pub inscription: Option<Inscription>,
}

impl Server {
    async fn api_transaction(
        Extension(index): Extension<Arc<Index>>,
        Path(txid): Path<Txid>,
    ) -> ServerResult<Json<ApiTransactionResponse>> {
        let inscription = index.get_inscription_by_id(txid.into())?;

        let block_hash = index.get_transaction_blockhash(txid)?;

        Ok(Json(ApiTransactionResponse {
            transaction: index.get_transaction(txid)?.ok_or_not_found(|| format!("transaction {txid}"))?,
            block_hash,
            inscription,
        }))
    }

    async fn status(Extension(index): Extension<Arc<Index>>) -> (StatusCode, &'static str) {
        if index.is_reorged() {
            (
                StatusCode::OK,
                "reorg detected, please rebuild the database.",
            )
        } else {
            (
                StatusCode::OK,
                StatusCode::OK.canonical_reason().unwrap_or_default(),
            )
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ApiSearchResponse {
    Block(String),
    Tx(String),
    TxOut(String),
    Inscription(String),
    Sat(String),
}

lazy_static! {
    static ref HASH: Regex = Regex::new(r"^[[:xdigit:]]{64}$").unwrap();
    static ref OUTPOINT: Regex = Regex::new(r"^[[:xdigit:]]{64}:\d+$").unwrap();
    static ref INSCRIPTION_ID: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
}

impl Server {
    async fn api_search(Extension(index): Extension<Arc<Index>>,
                        Query(search): Query<Search>) -> ServerResult<Json<ApiSearchResponse>> {
        Self::api_search_inner(&index, &search.query).map(Json)
    }

    fn api_search_inner(index: &Index, query: &str) -> ServerResult<ApiSearchResponse> {
        if HASH.is_match(query) {
            if index.block_header(query.parse().unwrap())?.is_some() {
                Ok(ApiSearchResponse::Block(format!("/api/block/{query}")))
            } else {
                Ok(ApiSearchResponse::Tx(format!("/api/tx/{query}")))
            }
        } else if OUTPOINT.is_match(query) {
            Ok(ApiSearchResponse::TxOut(format!("/api/output/{query}")))
        } else if INSCRIPTION_ID.is_match(query) {
            Ok(ApiSearchResponse::Inscription(format!("/api/inscription/{query}")))
        } else {
            Ok(ApiSearchResponse::Sat(format!("/api/sat/{query}")))
        }
    }

    async fn api_block_count(Extension(index): Extension<Arc<Index>>) -> ServerResult<Json<u64>> {
        Ok(Json(index.block_count()?))
    }

    async fn input(
        Extension(page_config): Extension<Arc<PageConfig>>,
        Extension(index): Extension<Arc<Index>>,
        Path(path): Path<(u64, usize, usize)>,
    ) -> Result<PageHtml<InputHtml>, ServerError> {
        let not_found = || format!("input /{}/{}/{}", path.0, path.1, path.2);

        let block = index
            .get_block_by_height(path.0)?
            .ok_or_not_found(not_found)?;

        let transaction = block
            .txdata
            .into_iter()
            .nth(path.1)
            .ok_or_not_found(not_found)?;

        let input = transaction
            .input
            .into_iter()
            .nth(path.2)
            .ok_or_not_found(not_found)?;

        Ok(InputHtml { path, input }.page(page_config, index.has_sat_index()?))
    }

    async fn content(
        Extension(index): Extension<Arc<Index>>,
        Extension(config): Extension<Arc<Config>>,
        Path(inscription_id): Path<InscriptionId>,
    ) -> ServerResult<Response> {
        if config.is_hidden(inscription_id) {
            return Ok(PreviewUnknownHtml.into_response());
        }

        let inscription = index
            .get_inscription_by_id(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        Ok(
            Self::content_response(inscription)
                .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
                .into_response(),
        )
    }

    fn content_response(inscription: Inscription) -> Option<(HeaderMap, Vec<u8>)> {
        let mut headers = HeaderMap::new();

        headers.insert(
            header::CONTENT_TYPE,
            inscription
                .content_type()
                .unwrap_or("application/octet-stream")
                .parse()
                .unwrap(),
        );
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'unsafe-eval' 'unsafe-inline' data:"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=31536000, immutable"),
        );

        Some((headers, inscription.into_body()?))
    }

    async fn preview(
        Extension(index): Extension<Arc<Index>>,
        Extension(config): Extension<Arc<Config>>,
        Path(inscription_id): Path<InscriptionId>,
    ) -> ServerResult<Response> {
        if config.is_hidden(inscription_id) {
            return Ok(PreviewUnknownHtml.into_response());
        }

        let inscription = index
            .get_inscription_by_id(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        return match inscription.media() {
            Media::Audio => Ok(PreviewAudioHtml { inscription_id }.into_response()),
            Media::Iframe => Ok(
                Self::content_response(inscription)
                    .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
                    .into_response(),
            ),
            Media::Image => Ok(
                (
                    [(
                        header::CONTENT_SECURITY_POLICY,
                        "default-src 'self' 'unsafe-inline'",
                    )],
                    PreviewImageHtml { inscription_id },
                )
                    .into_response(),
            ),
            Media::Pdf => Ok(
                (
                    [(
                        header::CONTENT_SECURITY_POLICY,
                        "script-src-elem 'self' https://cdn.jsdelivr.net",
                    )],
                    PreviewPdfHtml { inscription_id },
                )
                    .into_response(),
            ),
            Media::Text => {
                let content = inscription
                    .body()
                    .ok_or_not_found(|| format!("inscription {inscription_id} content"))?;
                Ok(
                    PreviewTextHtml {
                        text: str::from_utf8(content)
                            .map_err(|err| anyhow!("Failed to decode {inscription_id} text: {err}"))?,
                    }
                        .into_response(),
                )
            }
            Media::Unknown => Ok(PreviewUnknownHtml.into_response()),
            Media::Video => Ok(PreviewVideoHtml { inscription_id }.into_response()),
        };
    }
}

#[derive(Serialize)]
pub struct ApiInscriptionResponse {
    pub chain: Chain,
    pub genesis_fee: u64,
    pub genesis_height: u64,
    pub inscription: Inscription,
    pub inscription_id: InscriptionId,
    pub next: Option<InscriptionId>,
    pub number: u64,
    pub output: TxOut,
    pub previous: Option<InscriptionId>,
    pub sat: Option<Sat>,
    pub satpoint: SatPoint,
    pub timestamp: DateTime<Utc>,
}

impl Server {
    async fn api_inscription(
        Extension(page_config): Extension<Arc<PageConfig>>,
        Extension(index): Extension<Arc<Index>>,
        Path(inscription_id): Path<InscriptionId>,
    ) -> ServerResult<Json<ApiInscriptionResponse>> {
        let entry = index
            .get_inscription_entry(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        let inscription = index
            .get_inscription_by_id(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        let satpoint = index
            .get_inscription_satpoint_by_id(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        let output = index
            .get_transaction(satpoint.outpoint.txid)?
            .ok_or_not_found(|| format!("inscription {inscription_id} current transaction"))?
            .output
            .into_iter()
            .nth(satpoint.outpoint.vout.try_into().unwrap())
            .ok_or_not_found(|| format!("inscription {inscription_id} current transaction output"))?;

        let previous = if let Some(previous) = entry.number.checked_sub(1) {
            Some(
                index
                    .get_inscription_id_by_inscription_number(previous)?
                    .ok_or_not_found(|| format!("inscription {previous}"))?,
            )
        } else {
            None
        };

        let next = index.get_inscription_id_by_inscription_number(entry.number + 1)?;

        Ok(
            ApiInscriptionResponse {
                chain: page_config.chain,
                genesis_fee: entry.fee,
                genesis_height: entry.height,
                inscription,
                inscription_id,
                next,
                number: entry.number,
                output,
                previous,
                sat: entry.sat,
                satpoint,
                timestamp: timestamp(entry.timestamp),
            }
        ).map(Json)
    }
}

#[derive(Serialize)]
pub struct ApiInscriptionsResponse {
    pub inscriptions: Vec<InscriptionId>,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

impl Server {
    async fn api_inscriptions(
        Extension(page_config): Extension<Arc<PageConfig>>,
        Extension(index): Extension<Arc<Index>>,
    ) -> ServerResult<Json<ApiInscriptionsResponse>> {
        Self::inscriptions_inner( index, None).await.map(Json)
    }

    async fn api_inscriptions_from(
        Extension(index): Extension<Arc<Index>>,
        Path(from): Path<u64>,
    ) -> ServerResult<Json<ApiInscriptionsResponse>> {
        Self::inscriptions_inner( index, Some(from)).await.map(Json)
    }

    async fn inscriptions_inner(
        index: Arc<Index>,
        from: Option<u64>,
    ) -> ServerResult<ApiInscriptionsResponse> {
        let (inscriptions, prev, next) = index.get_latest_inscriptions_with_prev_and_next(100, from)?;
        Ok(
            ApiInscriptionsResponse {
                inscriptions,
                next,
                prev,
            }
        )
    }

    async fn redirect_http_to_https(
        Extension(mut destination): Extension<String>,
        uri: Uri,
    ) -> Redirect {
        if let Some(path_and_query) = uri.path_and_query() {
            destination.push_str(path_and_query.as_str());
        }

        Redirect::to(&destination)
    }
}
