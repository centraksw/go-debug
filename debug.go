// Copyright (c) 2015-2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

// Package debug implements access to ELF and TI-COFF object files by attempting
// to auto-detect which file type is in use.
package debug

import (
	"debug/elf"
	"errors"
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

	closer io.Closer
}

// NewFile creates a new file for access
func NewFile(r io.ReaderAt) (file *File, err error) {
	file = new(File)

	// Try ELF
	if f, err := elf.NewFile(r); err == nil {
		file.FileType = FileTypeELF

		file.Sections = make([]Section, len(f.Sections))
		for i, section := range f.Sections {
			file.Sections[i] = &elfSection{section}
		}

		return file, nil
	}

	// Try COFF
	if f, err := coff.NewFile(r); err == nil {
		file.FileType = FileTypeCOFF

		file.Sections = make([]Section, len(f.Sections))
		for i, section := range f.Sections {
			file.Sections[i] = &coffSection{section}
		}

		return file, nil
	}

	// Unsupported file type
	return nil, errors.New("unsupported debug file type")
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
