use crate::*;
use anyhow::Result;
use bendy::decoding::FromBencode;
use bendy::encoding::ToBencode;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;

pub fn parse_meta_file(path: &Path) -> Result<MetaInfoFile> {
    let bytes = fs::read(path)?;
    let res = MetaInfoFile::from_bencode(&bytes).map_err(|e| anyhow::anyhow!(e))?;
    Ok(res)
}

fn create_info_hash(info: InfoFile) -> Result<Vec<u8>> {
    let info = info.to_bencode().map_err(|e| anyhow::anyhow!(e))?;
    let mut hasher = Sha1::new();
    hasher.update(info);
    let res = hasher.finalize();
    Ok(res.to_vec())
}

pub fn get_info_hash_hex_string(info: InfoFile) -> Result<String> {
    let hashed = create_info_hash(info)?;
    let res = hashed
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    Ok(res)
}

pub fn get_info_hash_urlencoded(info: InfoFile) -> Result<String> {
    let hashed = get_info_hash_hex_string(info)?;
    let pair = &[("info_hash", &hashed[..])];
    let res = serde_urlencoded::to_string(pair)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::util::*;

    fn example_meta_file() -> Result<MetaInfoFile> {
        let path =
            std::path::PathBuf::try_from("test_assets/RogueTransmissions0nFrequency01.torrent")?;
        let parsed = parse_meta_file(&path)?;
        Ok(parsed)
    }

    #[test]
    fn parse_from_torrent_file() -> Result<()> {
        let example = example_meta_file().expect("example meta file should be valid");
        assert_eq!(
            example.announce,
            "udp://tracker.opentrackr.org:1337/announce".to_string()
        );
        Ok(())
    }

    #[test]
    fn calc_info_hash_string() -> Result<()> {
        let rogue_info_hash = "71e17c5bad17c59f02267406c0c9af496da9f389";
        let example = example_meta_file()?;
        let hashed = get_info_hash_hex_string(example.info)?;
        assert_eq!(rogue_info_hash, hashed);
        Ok(())
    }

    #[test]
    fn calc_info_hash_urlencoded() -> Result<()> {
        let rogue_info_hash = "71e17c5bad17c59f02267406c0c9af496da9f389";
        let example = example_meta_file()?;
        let hashed = get_info_hash_urlencoded(example.info)?;
        assert_eq!(rogue_info_hash, hashed);
        Ok(())
    }
}
