// Copyright (c) 2015-2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

// Package debug implements access to ELF and TI-COFF object files by attempting
// to auto-detect which file type is in use.
package debug

import (
	"debug/elf"
	"fmt"
	"io"
	"os"

	"github.com/awarepoint/go-debug/coff"
)

type FileType int

const (
	FileTypeUnknown FileType = iota
	FileTypeELF
	FileTypeCOFF
)

func (t FileType) String() string {
	switch t {
	case FileTypeELF:
		return "ELF"
	case FileTypeCOFF:
		return "TI-COFF"
	}
	return fmt.Sprintf("FileType%d", t)
}

type File struct {
	// FileType is the type of debug file, the zero value means the file type is
	// unknown.
	FileType FileType

	// Sections is a slice of debug sections.
	Sections []Section

	Symbols []Symbol

	closer io.Closer
}

// NewFile creates a new file for access
func NewFile(r io.ReaderAt) (file *File, err error) {
	file = new(File)

	es := make(ErrorSlice, 0)

	var ef *elf.File
	ef, err = elf.NewFile(r)
	if err == nil {
		file.FileType = FileTypeELF

		file.Sections = make([]Section, len(ef.Sections))
		for i, section := range ef.Sections {
			file.Sections[i] = &elfSection{section}
		}

		var symbols []elf.Symbol
		symbols, err = ef.Symbols()
		if err != nil {
			return
		}
		file.Symbols = make([]Symbol, len(symbols))
		for i := 0; i < len(file.Symbols); i++ {
			file.Symbols[i].Name = symbols[i].Name
			file.Symbols[i].Value = symbols[i].Value
			file.Symbols[i].Size = symbols[i].Size
		}

		return file, nil
	} else {
		es = append(es, fmt.Errorf("debug/elf: %v", err))
	}

	// Try COFF
	var cf *coff.File
	cf, err = coff.NewFile(r)
	if err == nil {
		file.FileType = FileTypeCOFF

		file.Sections = make([]Section, len(cf.Sections))
		for i, section := range cf.Sections {
			file.Sections[i] = &coffSection{section}
		}

		var symbols []coff.Symbol
		symbols, err = cf.Symbols()
		if err != nil {
			return
		}
		file.Symbols = make([]Symbol, len(symbols))
		for i := 0; i < len(file.Symbols); i++ {
			file.Symbols[i].Name = symbols[i].Name
			file.Symbols[i].Value = uint64(symbols[i].Value)
			if symbols[i].AuxiliaryEntry != nil {
				file.Symbols[i].Size = uint64(symbols[i].AuxiliaryEntry.Size)
			}
		}

		return file, nil
	} else {
		es = append(es, fmt.Errorf("debug/coff: %v", err))
	}

	return nil, es
}

// Open opens a debug file given a path.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	df, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	df.closer = f

	return df, nil
}

// Close closes the underlying file if there is one.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

type Section interface {
	io.ReaderAt
	Open() io.ReadSeeker

	Name() string
	Address() uint64
	Size() uint64
}

var _ Section = (*coffSection)(nil)

type coffSection struct {
	s *coff.Section
}

func (section *coffSection) ReadAt(p []byte, off int64) (n int, err error) {
	return section.s.ReadAt(p, off)
}

func (section *coffSection) Open() io.ReadSeeker {
	return section.s.Open()
}

func (section *coffSection) Name() string {
	return section.s.Name
}

func (section *coffSection) Address() uint64 {
	return uint64(section.s.PhysicalAddress)
}

func (section *coffSection) Size() uint64 {
	return uint64(section.s.Size)
}

var _ Section = (*elfSection)(nil)

type elfSection struct {
	s *elf.Section
}

func (section *elfSection) ReadAt(p []byte, off int64) (n int, err error) {
	return section.s.ReadAt(p, off)
}

func (section *elfSection) Open() io.ReadSeeker {
	return section.s.Open()
}

func (section *elfSection) Name() string {
	return section.s.Name
}

func (section *elfSection) Address() uint64 {
	return uint64(section.s.Addr)
}

func (section *elfSection) Size() uint64 {
	return uint64(section.s.Size)
}

type Symbol struct {
	Name  string
	Value uint64
	Size  uint64
}

type ErrorSlice []error

func Errors(err error) (errs []error) {
	es, ok := err.(ErrorSlice)
	if ok {
		errs = []error(es)
	} else {
		errs = make([]error, 1)
		errs[0] = err
	}
	return
}

func (es ErrorSlice) Error() string {
	return fmt.Sprintf("%d errors returned", len(es))
}
