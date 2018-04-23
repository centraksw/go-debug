// Copyright (c) 2015-2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

// Package coff implements access to TI-COFF object files.
package coff

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

var ErrInvalidTargetID = errors.New("invalid target ID")

// A File represents an open COFF file.
type File struct {
	FileHeader

	// OptionalFileHeader is nil if it exists, otherwise it is non-nil.
	OptionalFileHeader *OptionalFileHeader

	Sections []*Section

	symbols []Symbol

	closer io.Closer
}

func NewFile(r io.ReaderAt) (file *File, err error) {
	file = new(File)

	var (
		sr     = io.NewSectionReader(r, 0, 1<<63-1)
		offset int64
		chars  [8]byte
		name   string
	)

	// Read and validate the file header
	err = binary.Read(sr, binary.LittleEndian, &file.FileHeader)
	if err != nil {
		return
	}

	if !IsValidTargetID(&file.FileHeader) {
		return nil, ErrInvalidTargetID
	}

	offset += int64(binary.Size(file.FileHeader))

	if file.OptionalFileHeaderSize > 0 {
		file.OptionalFileHeader = new(OptionalFileHeader)
		err = binary.Read(sr, binary.LittleEndian, file.OptionalFileHeader)
		if err != nil {
			return
		}

		offset += int64(binary.Size(file.OptionalFileHeader))
	}

	// Skip ahead to read the string table
	sr.Seek(int64(file.SymbolTableStartAddress)+(int64(file.NumSymbolTableEntries)*18), 0)
	stringTable, err := ioutil.ReadAll(sr)
	if err != nil {
		return
	}

	// Reset to beginning of section headers
	sr.Seek(offset, 0)

	// Read all section headers
	file.Sections = make([]*Section, file.NumSections)
	for i := 0; i < len(file.Sections); i++ {
		section := new(Section)
		header := new(sectionHeader)

		err = binary.Read(sr, binary.LittleEndian, &chars)
		if err != nil {
			return
		}
		err = binary.Read(sr, binary.LittleEndian, header)
		if err != nil {
			return
		}

		offset += int64(binary.Size(chars))
		offset += int64(binary.Size(header))

		name, err = getString(stringTable, chars)
		if err != nil {
			return
		}

		section.SectionHeader = SectionHeader{
			Name:                     name,
			PhysicalAddress:          header.PhysicalAddress,
			VirtualAddress:           header.VirtualAddress,
			Size:                     header.Size,
			RawDataAddress:           header.RawDataAddress,
			RelocationEntriesAddress: header.RelocationEntriesAddress,
			NumRelocationEntries:     header.NumRelocationEntries,
			Flags:                    SectionHeaderFlags(header.Flags),
			MemoryPageNumber:         header.MemoryPageNumber,
		}

		sr.Seek(0, 0)
		section.sr = io.NewSectionReader(r, int64(section.RawDataAddress), int64(section.Size))
		sr.Seek(offset, 0)
		file.Sections[i] = section
	}

	// Read symbol table
	sr.Seek(int64(file.SymbolTableStartAddress), 0)
	file.symbols = make([]Symbol, 0, file.NumSymbolTableEntries)
	for i := file.NumSymbolTableEntries; i > 0; i-- {
		var sym symbol

		err = binary.Read(sr, binary.LittleEndian, &chars)
		if err != nil {
			return
		}
		err = binary.Read(sr, binary.LittleEndian, &sym)
		if err != nil {
			return
		}

		name, err = getString(stringTable, chars)
		if err != nil {
			return
		}

		// Check if any auxiliary entries exist, these also count towards the
		// total symbol entry count.
		var auxEntry *AuxiliaryEntry
		if sym.NumAuxEntries == 1 {
			i--
			auxEntry = new(AuxiliaryEntry)

			err = binary.Read(sr, binary.LittleEndian, auxEntry)
			if err != nil {
				return
			}
		}

		file.symbols = append(file.symbols, Symbol{
			Name:           name,
			Value:          sym.Value,
			SectionNumber:  sym.SectionNumber,
			StorageClass:   StorageClass(sym.StorageClass),
			NumAuxEntries:  sym.NumAuxEntries,
			AuxiliaryEntry: auxEntry,
		})
	}

	return
}

func getString(stringTable []byte, name [8]byte) (string, error) {
	if name[0] == 0 && name[1] == 0 && name[2] == 0 && name[3] == 0 {
		// TODO: Offset into the string table
		offset := (uint32(name[7]) << 24) | (uint32(name[6]) << 16) | (uint32(name[5]) << 8) | (uint32(name[4]) << 0)

		bs, err := bufio.NewReader(bytes.NewReader(stringTable[offset:])).ReadBytes(0x00)
		if err != nil {
			return "", err
		}

		return string(bs[0 : len(bs)-1]), nil
	} else {
		return strings.TrimRight(string(name[:]), "\x00"), nil
	}
}

func Open(name string) (f *File, err error) {
	of, err := os.Open(name)
	if err != nil {
		return
	}

	f, err = NewFile(of)
	if err != nil {
		of.Close()
		return
	}

	f.closer = of
	return
}

func (f *File) Symbols() ([]Symbol, error) {
	return f.symbols, nil
}

func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	} else {
		return nil
	}
}

// A FileHeader represents a COFF file header.
type FileHeader struct {
	Version                 uint16
	NumSections             uint16
	Timestamp               uint32
	SymbolTableStartAddress uint32
	NumSymbolTableEntries   uint32
	OptionalFileHeaderSize  uint16
	Flags                   uint16
	TargetID                TargetID
}

// IsValidTargetID checks if the target ID matches those defined in the
// TI-COFF specification.
func IsValidTargetID(header *FileHeader) (valid bool) {
	_, valid = targetIDMap[header.TargetID]
	return
}

const (
	FLAG_RELFLG   uint16 = 0x0001
	FLAG_EXEC            = 0x0002
	FLAG_LNNO            = 0x0004
	FLAG_LSYMS           = 0x0008
	FLAG_LITTLE          = 0x0100
	FLAG_BIG             = 0x0200
	FLAG_SYMMERGE        = 0x1000
)

type TargetID uint16

var targetIDMap = map[TargetID]string{
	0x0097: "TMS470",
	0x0098: "TMS320C5400",
	0x0099: "TMS320C6000",
	0x009C: "TMS320C5500",
	0x009D: "TMS320C2800",
	0x00A0: "MSP430",
	0x00A1: "TMS320C5500+",
}

func (tid TargetID) String() string {
	var s string
	if deviceFamily, exists := targetIDMap[tid]; exists {
		s = deviceFamily
	} else {
		s = "Unknown"
	}
	return fmt.Sprintf("%s (0x%04X)", s, uint16(tid))
}

// An OptionalFileHeader represents a COFF file optional header.
type OptionalFileHeader struct {
	MagicNumber                 uint16
	Version                     uint16
	ExecuteableCodeSize         uint32
	InitializedDataSize         uint32
	UninitializedDataSize       uint32
	EntryPoint                  uint32
	BeginAddressExecutableCode  uint32
	BeginAddressInitializedData uint32
}

const OptionalFileHeaderMagicNumber uint16 = 0x0108

// A Section represents a COFF file code section.
type Section struct {
	SectionHeader

	io.ReaderAt
	sr *io.SectionReader

	// TODO: Relocation information
}

func (s *Section) Open() io.ReadSeeker {
	return io.NewSectionReader(s.sr, 0, 1<<63-1)
}

// A SectionHeader represent a COFF file code section header.
type SectionHeader struct {
	Name                     string
	PhysicalAddress          uint32
	VirtualAddress           uint32
	Size                     uint32
	RawDataAddress           uint32
	RelocationEntriesAddress uint32
	NumRelocationEntries     uint32
	Flags                    SectionHeaderFlags
	MemoryPageNumber         uint16
}

type SectionHeaderFlags uint32

const (
	STYP_REG    SectionHeaderFlags = 0x00000000 // Regular section (allocated, relocated, loaded)
	STYP_DSECT                     = 0x00000001 // Dummy section (relocated, not allocated, not loaded)
	STYP_NOLOAD                    = 0x00000002 // Noload section (allocated, relocated, not loaded)
	STYP_GROUP                     = 0x00000004 // Grouped section (formed from several input sections). Other devices: Reserved
	STYP_PAD                       = 0x00000008 // Padding section (loaded, not allocated, not relocated). Other devices: Reserved
	STYP_COPY                      = 0x00000010 // Copy section (relocated, loaded, but not allocated; relocation entries are processed normally)
	STYP_TEXT                      = 0x00000020 // Section contains executable code
	STYP_DATA                      = 0x00000040 // Section contains initialized data
	STYP_BSS                       = 0x00000080 // Section contains uninitialized data
	STYP_BLOCK                     = 0x00001000 // Alignment used as a blocking factor.
	STYP_PASS                      = 0x00002000 // Section should pass through unchanged.
	STYP_CLINK                     = 0x00004000 // Section requires conditional linking
	STYP_VECTOR                    = 0x00008000 // Section contains vector table.
	STYP_PADDED                    = 0x00010000 // section has been padded
)

// A SectionHeader represent a COFF file code section header.
type sectionHeader struct {
	// name [8]byte
	PhysicalAddress          uint32
	VirtualAddress           uint32
	Size                     uint32
	RawDataAddress           uint32
	RelocationEntriesAddress uint32
	_                        uint32
	NumRelocationEntries     uint32
	_                        uint32
	Flags                    uint32
	_                        uint16
	MemoryPageNumber         uint16
}

type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int16
	StorageClass  StorageClass
	NumAuxEntries uint8
	// AuxiliaryEntry will be non-nil if NumAuxEntries == 1
	AuxiliaryEntry *AuxiliaryEntry
}

type StorageClass uint8

const (
	C_NULL    StorageClass = 0   // No storage class
	C_AUTO                 = 1   // Reserved
	C_EXT                  = 2   // External definition
	C_STAT                 = 3   // Static
	C_REG                  = 4   // Reserved
	C_EXTREF               = 5   // External reference
	C_LABEL                = 6   // Label
	C_ULABEL               = 7   // Undefined label
	C_MOS                  = 8   // Reserved
	C_ARG                  = 9   // Reserved
	C_STRTAG               = 10  // Reserved
	C_MOU                  = 11  // Reserved
	C_UNTAG                = 12  // Reserved
	C_TPDEF                = 13  // Reserved
	C_USTATIC              = 14  // Undefined static
	C_ENTAG                = 15  // Reserved
	C_MOE                  = 16  // Reserved
	C_REGPARM              = 17  // Reserved
	C_FIELD                = 18  // Reserved
	C_UEXT                 = 19  // Tentative external definition
	C_STATLAB              = 20  // Static load time label
	C_EXTLAB               = 21  // External load time label
	C_VARARG               = 27  // Last declared parameter of a function with a variable number of arguments
	C_BLOCK                = 100 // Reserved
	C_FCN                  = 101 // Reserved
	C_EOS                  = 102 // Reserved
	C_FILE                 = 103 // Reserved
	C_LINE                 = 104 // Used only by utility programs
)

func (c StorageClass) String() string {
	var s string
	switch c {
	default:
		s = "Unknown"
	case C_NULL:
		s = "C_NULL"
	case C_AUTO:
		s = "C_AUTO"
	case C_EXT:
		s = "C_EXT"
	case C_STAT:
		s = "C_STAT"
	case C_REG:
		s = "C_REG"
	case C_EXTREF:
		s = "C_EXTREF"
	case C_LABEL:
		s = "C_LABEL"
	case C_ULABEL:
		s = "C_ULABEL"
	case C_MOS:
		s = "C_MOS"
	case C_ARG:
		s = "C_ARG"
	case C_STRTAG:
		s = "C_STRTAG"
	case C_MOU:
		s = "C_MOU"
	case C_UNTAG:
		s = "C_UNTAG"
	case C_TPDEF:
		s = "C_TPDEF"
	case C_USTATIC:
		s = "C_USTATIC"
	case C_ENTAG:
		s = "C_ENTAG"
	case C_MOE:
		s = "C_MOE"
	case C_REGPARM:
		s = "C_REGPARM"
	case C_FIELD:
		s = "C_FIELD"
	case C_UEXT:
		s = "C_UEXT"
	case C_STATLAB:
		s = "C_STATLAB"
	case C_EXTLAB:
		s = "C_EXTLAB"
	case C_VARARG:
		s = "C_VARARG"
	case C_BLOCK:
		s = "C_BLOCK"
	case C_FCN:
		s = "C_FCN"
	case C_EOS:
		s = "C_EOS"
	case C_FILE:
		s = "C_FILE"
	case C_LINE:
		s = "C_LINE"
	}
	return fmt.Sprintf("%s (%d)", s, uint8(c))
}

type symbol struct {
	// name [8]byte
	Value         uint32
	SectionNumber int16
	_             uint16
	StorageClass  uint8
	NumAuxEntries uint8
}

type AuxiliaryEntry struct {
	Size                   uint32
	NumRelocationEntries   uint16
	NumOfLineNumberEntries uint16
	_                      [10]byte
}
