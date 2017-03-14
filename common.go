/*
 * Copyright (c) 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package framestream

import "bufio"
import "bytes"
import "encoding/binary"
import "io"

type ControlFrame struct {
    ControlType     uint32
    ContentTypes    [][]byte
}

func readBE32(reader *bufio.Reader) (val uint32, err error) {
    err = binary.Read(reader, binary.BigEndian, &val)
    if err != nil {
        return 0, err
    }
    return
}

func readEscape(reader *bufio.Reader) (stopped bool, err error) {
    escape, err := readBE32(reader)
    if err != nil || escape != 0 {
        stopped = true
        return
    }
    if escape != 0 {
        err = ErrDecode
        return
    }
    return
}

func readControlFrame(reader *bufio.Reader) (cf *ControlFrame, err error) {
    cf = new(ControlFrame)

    // Read the control frame length.
    controlFrameLen, err := readBE32(reader)
    if err != nil {
        return
    }

    // Enforce limits on control frame size.
    if controlFrameLen < 4 || controlFrameLen > MAX_CONTROL_FRAME_SIZE {
        err = ErrDecode
        return
    }

    // Read the control frame.
    controlFrameData := make([]byte, controlFrameLen)
    n, err := io.ReadFull(reader, controlFrameData)
    if err != nil || uint32(n) != controlFrameLen {
        return
    }

    // Read the control frame type.
    p := bytes.NewBuffer(controlFrameData[0:4])
    err = binary.Read(p, binary.BigEndian, &cf.ControlType)
    if err != nil {
        return
    }

    // Read the control fields.
    var pos uint32 = 8
    for pos < controlFrameLen  {
        controlFieldType := binary.BigEndian.Uint32(controlFrameData[pos-4:pos])
        switch controlFieldType {
            case CONTROL_FIELD_CONTENT_TYPE: {
                pos += 4
                if pos > controlFrameLen {
                    return cf, ErrDecode
                }
                lenContentType := binary.BigEndian.Uint32(controlFrameData[pos-4:pos])
                if lenContentType > MAX_CONTROL_FRAME_SIZE {
                   return cf, ErrDecode
                }
                pos += lenContentType
                if pos > controlFrameLen {
                    return cf, ErrDecode
                }
                contentType := make([]byte, lenContentType)
                copy(contentType, controlFrameData[pos-lenContentType:pos])
                cf.ContentTypes = append(cf.ContentTypes, contentType)
            }
            default:
               return cf, ErrDecode
        }
    }

    // Enforce limits on number of ContentType fields.
    lenContentTypes := len(cf.ContentTypes)
    switch cf.ControlType {
        case CONTROL_START:
            if lenContentTypes > 1 {
                return cf, ErrDecode
            }
        case CONTROL_STOP, CONTROL_FINISH:
            if lenContentTypes > 0 {
                return cf, ErrDecode
            }
    }

    return
}

func matchContentTypes(a [][]byte, b [][]byte) (c [][]byte) {
    matched := make([][]byte, 0, 0)
    for _, contentTypeA := range a {
        for _, contentTypeB := range b {
            if bytes.Compare(contentTypeA, contentTypeB) == 0 {
                matched = append(matched, contentTypeA)
            }
        }
    }
    return matched
}

func readControlFrameType(reader *bufio.Reader, t uint32) (cf *ControlFrame, err error) {
    _, err = readEscape(reader)
    if err != nil {
        return
    }
    cf, err = readControlFrame(reader)
    if err != nil {
        return
    }
    if cf.ControlType != t {
        return cf, ErrDecode
    }
    return
}
