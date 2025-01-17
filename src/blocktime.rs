use super::*;

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum Blocktime {
  Confirmed(DateTime<Utc>),
  Expected(DateTime<Utc>),
}

impl Blocktime {
  pub(crate) fn confirmed(seconds: u32) -> Self {
    Self::Confirmed(timestamp(seconds))
  }

  pub(crate) fn timestamp(self) -> DateTime<Utc> {
    match self {
      Self::Confirmed(timestamp) | Self::Expected(timestamp) => timestamp,
    }
  }

  pub(crate) fn suffix(self) -> &'static str {
    match self {
      Self::Confirmed(_) => "",
      Self::Expected(_) => " (expected)",
    }
  }
}
