//  Copyright (C) 2019 - 2023 Illirgway
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

package xautoserver

import (
	"crypto/tls"
	"errors"
	"os"
)

var errNotFile = errors.New("entity is not a regular file")

func helperWatchCertsChanges(c *TLSConfig, mtime int64) (*certInfo, error) {

	certMtime, err := getFileMtime(c.Cert)

	if err != nil {
		return nil, err
	}

	keyMtime, err := getFileMtime(c.Key)

	if err != nil {
		return nil, err
	}

	if uts := maxUTS(mtime, certMtime, keyMtime); uts > mtime {
		return loadCertInfo(c.Cert, c.Key, uts)
	}

	return nil, nil
}

func loadCertInfo(certFile, keyFile string, mtime int64) (*certInfo, error) {

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)

	if err != nil {
		return nil, err
	}

	ci := newCertInfo(&cert, mtime)

	return ci, nil
}

func getFileMtime(filename string) (int64, error) {

	f, err := os.Open(filename)

	if err != nil {
		return 0, err
	}

	defer f.Close()

	fi, err := f.Stat()

	if err != nil {
		return 0, err
	}

	if !fi.Mode().IsRegular() {
		return 0, errNotFile
	}

	return fi.ModTime().Unix(), nil
}

func maxUTS(max int64, uts ...int64) int64 {

	for _, t := range uts {
		if max < t {
			max = t
		}
	}

	return max
}