package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func logf(format string, args ...interface{}) {
	fmt.Printf("[c2d] "+format+"\n", args...)
}

// readLine 读取一行（'\n' 结尾），限制最大长度，防御超大行
func readLine(r *bufio.Reader, max int) (string, error) {
	var buf bytes.Buffer
	for {
		chunk, err := r.ReadSlice('\n')
		buf.Write(chunk)
		if buf.Len() > max {
			return "", errors.New("行超长")
		}
		if err == nil {
			line := buf.Bytes()
			line = bytes.TrimRight(line, "\r\n")
			return string(line), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // 继续读到 '\n'
		}
		if errors.Is(err, io.EOF) && buf.Len() > 0 {
			return buf.String(), nil
		}
		return "", err
	}
}
