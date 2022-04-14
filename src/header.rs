//             DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2018 Thomas Bailleux <thomas@bailleux.me>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//
// Author: zadig <thomas chr(0x40) bailleux.me>

use std::convert::TryInto;
use std::io::Read;
use std::usize;

impl<'ole> super::ole::Reader<'ole> {
    pub(crate) fn parse_header(&mut self) -> Result<(), super::error::Error> {
        // read the header
        let mut header = vec![0u8; super::constants::HEADER_SIZE];
        self.read(&mut header)?;

        // initializes the return variable
        let result: Result<(), super::error::Error>;

        // Check file identifier
        if super::constants::IDENTIFIER != header[0..8] {
            result = Err(super::error::Error::InvalidOLEFile);
        } else {
            self.uid = header[8..24].to_vec();
            self.revision_number = Some(u16::from_le_bytes(header[24..26].try_into().unwrap()));
            self.version_number = Some(u16::from_le_bytes(header[26..28].try_into().unwrap()));

            // Check little-endianness; big endian not yet supported
            if header[28..30] == super::constants::BIG_ENDIAN_IDENTIFIER {
                result = Err(super::error::Error::NotImplementedYet);
            } else if header[28..30] != super::constants::LITTLE_ENDIAN_IDENTIFIER {
                result = Err(super::error::Error::InvalidOLEFile);
            } else {
                // Sector size
                let mut k = u16::from_le_bytes(header[30..32].try_into().unwrap());

                // if k >= 16, it means that the sector size equals 2 ^ k, which
                // is impossible.
                if k >= 16 {
                    result = Err(super::error::Error::BadSizeValue("Overflow on sector size"));
                } else {
                    self.sec_size = Some(2_usize.pow(k as u32));

                    // Short sector size
                    k = u16::from_le_bytes(header[32..34].try_into().unwrap());

                    // same for sector size
                    if k >= 16 {
                        result = Err(super::error::Error::BadSizeValue(
                            "Overflow on short sector size",
                        ));
                    } else {
                        self.short_sec_size = Some(2_usize.pow(k as u32));

                        // Total number of sectors used for the sector allocation table
                        let sat = Vec::with_capacity(
                            (*self.sec_size.as_ref().unwrap() / 4)
                                * u32::from_le_bytes(header[44..48].try_into().unwrap()) as usize,
                        );

                        // SecID of the first sector of directory stream
                        let dsat = vec![u32::from_le_bytes(header[48..52].try_into().unwrap())];

                        // Minimum size of a standard stream (bytes)
                        self.minimum_standard_stream_size =
                            Some(u32::from_le_bytes(header[56..60].try_into().unwrap()) as usize);

                        // standard says that this value has to be greater
                        // or equals to 4096
                        if *self.minimum_standard_stream_size.as_ref().unwrap() < 4096_usize {
                            result = Err(super::error::Error::InvalidOLEFile);
                        } else {
                            // secID of the first sector of the SSAT & Total number
                            // of sectors used for the short-sector allocation table
                            let mut ssat = Vec::with_capacity(
                                u32::from_le_bytes(header[64..68].try_into().unwrap()) as usize
                                    * (*self.sec_size.as_ref().unwrap() / 4),
                            );
                            ssat.push(u32::from_le_bytes(header[60..64].try_into().unwrap()));

                            // secID of first sector of the master sector allocation table
                            // & Total number of sectors used for
                            // the master sector allocation table
                            let mut msat = vec![super::constants::FREE_SECID_U32; 109];
                            if header[68..72] != super::constants::END_OF_CHAIN_SECID {
                                msat.resize(
                                    109_usize
                                        + u32::from_le_bytes(header[72..76].try_into().unwrap())
                                            as usize
                                            * (*self.sec_size.as_ref().unwrap() / 4),
                                    super::constants::FREE_SECID_U32,
                                );
                            }
                            self.sat = Some(sat);
                            self.msat = Some(msat);
                            self.dsat = Some(dsat);
                            self.ssat = Some(ssat);

                            // now we build the MSAT
                            self.build_master_sector_allocation_table(&header)?;
                            result = Ok(())
                        }
                    }
                }
            }
        }

        result
    }

    /// Build the Master Sector Allocation Table (MSAT)
    fn build_master_sector_allocation_table(
        &mut self,
        header: &[u8],
    ) -> Result<(), super::error::Error> {
        // First, we build the master sector allocation table from the header
        let mut total_sec_id_read = self.read_sec_ids(&header[76..], 0);

        // Check if additional sectors are used for building the msat
        if total_sec_id_read == 109 {
            let sec_size = *self.sec_size.as_ref().unwrap();
            let mut sec_id = u32::from_le_bytes(header[68..72].try_into().unwrap());
            let mut buffer = vec![0u8; 0];

            while sec_id != super::constants::END_OF_CHAIN_SECID_U32 {
                let relative_offset = sec_id as usize * sec_size;

                // check if we need to read more data
                if buffer.len() <= relative_offset + sec_size {
                    let new_len = (sec_id + 1) as usize * sec_size;
                    buffer.resize(new_len, 0xFFu8);
                    self.read(&mut buffer[relative_offset..relative_offset + sec_size])?;
                }
                total_sec_id_read += self.read_sec_ids(
                    &buffer[relative_offset..relative_offset + sec_size - 4],
                    total_sec_id_read,
                );
                sec_id = u32::from_le_bytes(buffer[buffer.len() - 4..].try_into().unwrap());
            }
            // save the buffer for later usage
            self.body = Some(buffer);
        }
        self.msat
            .as_mut()
            .unwrap()
            .resize(total_sec_id_read, super::constants::FREE_SECID_U32);

        if self.body.is_none() {
            self.body = Some(vec![]);
        }

        self.buf_reader
            .as_mut()
            .unwrap()
            .read_to_end(self.body.as_mut().unwrap())
            .map_err(super::error::Error::IOError)?;
        Ok(())
    }

    fn read_sec_ids(&mut self, buffer: &[u8], msat_offset: usize) -> usize {
        let mut i = 0usize;
        let mut offset = 0usize;
        let max_sec_ids = buffer.len() / 4;
        let msat = &mut self.msat.as_mut().unwrap()[msat_offset..];
        while i < max_sec_ids && buffer[offset..offset + 4] != super::constants::FREE_SECID {
            msat[i] = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap());
            offset += 4;
            i += 1;
        }

        i
    }
}
