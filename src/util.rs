use crate::*;
use bendy::decoding::{Error, FromBencode};
use std::fs;
use std::path::Path;

fn parse_meta_file(path: &Path) -> Result<MetaInfoFile, Error> {
    let bytes = fs::read(path)?;
    MetaInfoFile::from_bencode(&bytes)
}

#[cfg(test)]
mod tests {
    use crate::util::*;

    #[test]
    fn parse_from_torrent_file() -> Result<(), Error> {
        let path =
            std::path::PathBuf::try_from("test_assets/RogueTransmissions0nFrequency01.torrent")?;
        let parsed = parse_meta_file(&path)?;
        assert_eq!(
            parsed.announce,
            "udp://tracker.opentrackr.org:1337/".to_string()
        );
        Ok(())
    }
}
