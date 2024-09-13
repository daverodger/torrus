use bendy::decoding::Error;
use torrus::*;

fn main() -> Result<(), Error> {
    let path = std::path::PathBuf::try_from("test_assets/RogueTransmissions0nFrequency01.torrent")?;
    let parsed = parse_meta_file(&path)?;
    println!("{}", parsed);

    Ok(())
}
