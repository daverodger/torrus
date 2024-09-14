use anyhow::Result;
use torrus::*;

fn main() -> Result<()> {
    let path = std::path::PathBuf::try_from("test_assets/RogueTransmissions0nFrequency01.torrent")?;
    let parsed = parse_meta_file(&path)?;
    println!("{}", parsed);

    Ok(())
}
