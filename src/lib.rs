// #![allow(unused)]
use bendy::decoding::{Error as DecodeError, FromBencode, ResultExt};
use bendy::encoding::{Error, SingleItemEncoder, ToBencode};

#[derive(Debug, Eq, PartialEq)]
struct InfoDictSingleFile {
    // number of bytes in each piece (integer)
    piece_length: usize,
    // string consisting of the concatenation of all 20-byte SHA1 hash values
    // One per piece (byte string, i.e. not urlencoded)
    pieces: String,
    // (optional) this field is an integer. If it is set to "1",
    // the client MUST publish its presence to get other peers ONLY via the
    // trackers explicitly described in the metainfo file.
    // If this field is set to "0" or is not present,
    // the client may obtain peer from other means, e.g. PEX peer exchange, dht.
    // Here, "private" may be read as "no external peer source".
    private: Option<u8>,
    // filename (purely advisory)
    name: String,
    // length of the file in bytes
    length: usize,
    // (optional) a 32-character hexadecimal string corresponding to the MD5 sum of the file.
    // This is not used by BitTorrent at all,
    // but it is included by some programs for greater compatibility.
    md5sum: Option<String>,
}

impl ToBencode for InfoDictSingleFile {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"length", &self.length)?;
            if let Some(v) = &self.md5sum {
                e.emit_pair(b"md5sum", v)?;
            }
            e.emit_pair(b"name", &self.name)?;
            e.emit_pair(b"piece_length", &self.piece_length)?;
            e.emit_pair(b"pieces", &self.pieces)?;
            if let Some(v) = &self.private {
                e.emit_pair(b"private", v)?;
            }
            Ok(())
        })
    }
}

impl FromBencode for InfoDictSingleFile {
    const EXPECTED_RECURSION_DEPTH: usize = 3;

    fn decode_bencode_object(
        object: bendy::decoding::Object,
    ) -> Result<InfoDictSingleFile, DecodeError>
    where
        Self: Sized,
    {
        let mut name = None;
        let mut md5sum = None;
        let mut length = None;
        let mut piece_length = None;
        let mut pieces = None;
        let mut private = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"length", value) => {
                    length = usize::decode_bencode_object(value)
                        .context("length")
                        .map(Some)?;
                }
                (b"name", value) => {
                    name = String::decode_bencode_object(value)
                        .context("name")
                        .map(Some)?;
                }
                (b"md5sum", value) => {
                    md5sum = String::decode_bencode_object(value)
                        .context("md5sum")
                        .map(Some)?;
                }
                (b"private", value) => {
                    private = u8::decode_bencode_object(value)
                        .context("private")
                        .map(Some)?;
                }
                (b"pieces", value) => {
                    pieces = String::decode_bencode_object(value)
                        .context("pieces")
                        .map(Some)?;
                }
                (b"piece_length", value) => {
                    piece_length = usize::decode_bencode_object(value)
                        .context("piece_length")
                        .map(Some)?;
                }
                (unknown_field, _) => {
                    return Err(DecodeError::unexpected_field(String::from_utf8_lossy(
                        unknown_field,
                    )))
                }
            }
        }

        let length = length.ok_or_else(|| DecodeError::missing_field("length"))?;
        let name = name.ok_or_else(|| DecodeError::missing_field("name"))?;
        let pieces = pieces.ok_or_else(|| DecodeError::missing_field("pieces"))?;
        let piece_length =
            piece_length.ok_or_else(|| DecodeError::missing_field("piece_length"))?;

        Ok(InfoDictSingleFile {
            length,
            name,
            md5sum,
            pieces,
            piece_length,
            private,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct InfoDictMultiFile {
    // number of bytes in each piece (integer)
    piece_length: usize,
    // string consisting of the concatenation of all 20-byte SHA1 hash values
    // One per piece (byte string, i.e. not urlencoded)
    pieces: String,
    // (optional) this field is an integer. If it is set to "1",
    // the client MUST publish its presence to get other peers ONLY via the
    // trackers explicitly described in the metainfo file.
    // If this field is set to "0" or is not present,
    // the client may obtain peer from other means, e.g. PEX peer exchange, dht.
    // Here, "private" may be read as "no external peer source".
    private: Option<u8>,
    //  name of the directory in which to store all the files. This is purely advisory.
    name: String,
    // a list of dictionaries, one for each file.
    files: FileDict,
}

impl ToBencode for InfoDictMultiFile {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"files", &self.files)?;
            e.emit_pair(b"name", &self.name)?;
            e.emit_pair(b"piece_length", &self.piece_length)?;
            e.emit_pair(b"pieces", &self.pieces)?;
            if let Some(v) = &self.private {
                e.emit_pair(b"private", v)?;
            }
            Ok(())
        })
    }
}

impl FromBencode for InfoDictMultiFile {
    const EXPECTED_RECURSION_DEPTH: usize = 3;

    fn decode_bencode_object(
        object: bendy::decoding::Object,
    ) -> Result<InfoDictMultiFile, DecodeError>
    where
        Self: Sized,
    {
        let mut files = None;
        let mut name = None;
        let mut piece_length = None;
        let mut pieces = None;
        let mut private = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"files", value) => {
                    files = FileDict::decode_bencode_object(value)
                        .context("files")
                        .map(Some)?;
                }
                (b"name", value) => {
                    name = String::decode_bencode_object(value)
                        .context("name")
                        .map(Some)?;
                }
                (b"private", value) => {
                    private = u8::decode_bencode_object(value)
                        .context("private")
                        .map(Some)?;
                }
                (b"pieces", value) => {
                    pieces = String::decode_bencode_object(value)
                        .context("pieces")
                        .map(Some)?;
                }
                (b"piece_length", value) => {
                    piece_length = usize::decode_bencode_object(value)
                        .context("piece_length")
                        .map(Some)?;
                }
                (unknown_field, _) => {
                    return Err(DecodeError::unexpected_field(String::from_utf8_lossy(
                        unknown_field,
                    )))
                }
            }
        }

        let files = files.ok_or_else(|| DecodeError::missing_field("files"))?;
        let name = name.ok_or_else(|| DecodeError::missing_field("name"))?;
        let pieces = pieces.ok_or_else(|| DecodeError::missing_field("pieces"))?;
        let piece_length =
            piece_length.ok_or_else(|| DecodeError::missing_field("piece_length"))?;

        Ok(InfoDictMultiFile {
            files,
            name,
            pieces,
            piece_length,
            private,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct FileDict {
    // length of the file in bytes (integer)
    length: usize,
    md5sum: Option<String>,
    // a list containing one or more string elements
    // that together represent the path and filename.
    // Each element in the list corresponds to either
    // a directory name or (in the case of the final element) the filename.
    path: Vec<String>,
}

impl ToBencode for FileDict {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"length", &self.length)?;
            if let Some(s) = &self.md5sum {
                e.emit_pair(b"md5sum", s)?
            }
            e.emit_pair(b"path", &self.path)?;

            Ok(())
        })
    }
}

impl FromBencode for FileDict {
    const EXPECTED_RECURSION_DEPTH: usize = 2;

    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<FileDict, DecodeError>
    where
        Self: Sized,
    {
        let mut length = None;
        let mut md5sum = None;
        let mut path = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"length", value) => {
                    length = usize::decode_bencode_object(value)
                        .context("length")
                        .map(Some)?;
                }
                (b"md5sum", value) => {
                    md5sum = String::decode_bencode_object(value)
                        .context("md5sum")
                        .map(Some)?;
                }
                (b"path", value) => {
                    let mut result = Vec::new();
                    let mut list = value.try_into_list()?;
                    while let Some(p) = list.next_object()? {
                        result.push(String::decode_bencode_object(p).context("path")?);
                    }
                    path = (!result.is_empty()).then(|| result);
                }
                (unknown_field, _) => {
                    return Err(DecodeError::unexpected_field(String::from_utf8_lossy(
                        unknown_field,
                    )))
                }
            }
        }

        let length = length.ok_or_else(|| DecodeError::missing_field("length"))?;
        let path = path.ok_or_else(|| DecodeError::missing_field("path"))?;

        Ok(FileDict {
            length,
            md5sum,
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn example_file_dict() -> FileDict {
        FileDict {
            length: 100,
            md5sum: None,
            path: vec!["dir1/dir2/file.ext".to_string()],
        }
    }

    const FILE_ENCODED_WITHOUT_MD5: &[u8] = b"d6:lengthi100e4:pathl18:dir1/dir2/file.extee";
    const FILE_ENCODED_WITH_MD5: &[u8] =
        b"d6:lengthi100e6:md5sum7:fakesum4:pathl18:dir1/dir2/file.extee";

    #[test]
    fn encode_file_dict() -> Result<(), Error> {
        let mut example = example_file_dict();
        let encoded = example.to_bencode()?;
        assert_eq!(FILE_ENCODED_WITHOUT_MD5, encoded.as_slice());

        example.md5sum = Some("fakesum".to_string());
        let encoded = example.to_bencode()?;
        assert_eq!(FILE_ENCODED_WITH_MD5, encoded.as_slice());

        Ok(())
    }

    #[test]
    fn decode_file_dict() -> Result<(), DecodeError> {
        let decoded = FileDict::from_bencode(FILE_ENCODED_WITHOUT_MD5)?;
        let mut example = example_file_dict();
        assert_eq!(decoded, example);

        example.md5sum = Some("fakesum".to_string());
        let decoded = FileDict::from_bencode(FILE_ENCODED_WITH_MD5)?;
        assert_eq!(decoded, example);

        Ok(())
    }

    fn example_info_dict_multi_file() -> InfoDictMultiFile {
        InfoDictMultiFile {
            piece_length: 256,
            pieces: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            private: None,
            name: "example_directory".to_string(),
            files: example_file_dict(),
        }
    }

    const MULTI_ENCODED_WITHOUT_PRIVATE: &[u8] = b"d5:filesd6:lengthi100e4:pathl18:dir1/dir2/file.extee4:name17:example_directory12:piece_lengthi256e6:pieces64:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefe";
    const MULTI_ENCODED_WITH_PRIVATE: &[u8] = b"d5:filesd6:lengthi100e4:pathl18:dir1/dir2/file.extee4:name17:example_directory12:piece_lengthi256e6:pieces64:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef7:privatei1ee";

    #[test]
    fn encode_info_dict_multi_file() -> Result<(), Error> {
        let mut example = example_info_dict_multi_file();

        let encoded = example.to_bencode()?;
        assert_eq!(MULTI_ENCODED_WITHOUT_PRIVATE, encoded.as_slice());

        example.private = Some(1);
        let encoded = example.to_bencode()?;
        assert_eq!(MULTI_ENCODED_WITH_PRIVATE, encoded.as_slice());

        Ok(())
    }

    #[test]
    fn decode_info_dict_multi_file() -> Result<(), DecodeError> {
        let decoded = InfoDictMultiFile::from_bencode(MULTI_ENCODED_WITHOUT_PRIVATE)?;
        let mut example = example_info_dict_multi_file();
        assert_eq!(decoded, example);

        example.private = Some(1);
        let decoded = InfoDictMultiFile::from_bencode(MULTI_ENCODED_WITH_PRIVATE)?;
        assert_eq!(decoded, example);

        Ok(())
    }

    fn example_info_dict_single_file() -> InfoDictSingleFile {
        InfoDictSingleFile {
            piece_length: 256,
            pieces: "fakenews123".to_string(),
            private: None,
            length: 25600,
            name: "singlefile.txt".to_string(),
            md5sum: None,
        }
    }

    const SINGLE_ENCODED_WO_PRIV_SUM: &[u8] =
        b"d6:lengthi25600e4:name14:singlefile.txt12:piece_lengthi256e6:pieces11:fakenews123e";
    const SINGLE_ENCODED_W_SUM: &[u8] =
        b"d6:lengthi25600e6:md5sum4:hash4:name14:singlefile.txt12:piece_lengthi256e6:pieces11:fakenews123e";
    const SINGLE_ENCODED_FULL: &[u8] =
            b"d6:lengthi25600e6:md5sum4:hash4:name14:singlefile.txt12:piece_lengthi256e6:pieces11:fakenews1237:privatei1ee";

    #[test]
    fn encode_info_dict_single_file() -> Result<(), Error> {
        let mut example = example_info_dict_single_file();

        let encoded = example.to_bencode()?;
        assert_eq!(SINGLE_ENCODED_WO_PRIV_SUM, encoded.as_slice());

        example.md5sum = Some("hash".to_string());
        let encoded = example.to_bencode()?;
        assert_eq!(SINGLE_ENCODED_W_SUM, encoded.as_slice());

        example.private = Some(1);
        let encoded = example.to_bencode()?;
        assert_eq!(SINGLE_ENCODED_FULL, encoded.as_slice());

        Ok(())
    }

    #[test]
    fn decode_info_dict_single_file() -> Result<(), DecodeError> {
        let decoded = InfoDictSingleFile::from_bencode(SINGLE_ENCODED_WO_PRIV_SUM)?;
        let mut example = example_info_dict_single_file();
        assert_eq!(decoded, example);

        example.md5sum = Some("hash".to_string());
        let decoded = InfoDictSingleFile::from_bencode(SINGLE_ENCODED_W_SUM)?;
        assert_eq!(decoded, example);

        example.private = Some(1);
        let decoded = InfoDictSingleFile::from_bencode(SINGLE_ENCODED_FULL)?;
        assert_eq!(decoded, example);

        Ok(())
    }
}
