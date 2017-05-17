package strs

import (
    "strings"
)

func TrimEner(str string) string {
    return _trim(str, "\n")
}

func TrimSpace(str string) string {
    return _trim(str, " ")
}

func TrimSlash(str string) string {
    return _trim(str, "/")
}

func ReplaceTwoSpace(str string) string {
    return _replace(str, "  ", " ")
}

func ReplaceEnter(str string) string {
    return _replace(str, "\n", " ")
}

func ReplaceNine(str string) string {
    x := []byte(str)
    for k, v := range x {
        if v == 9 {
            x[k] = byte(32)
        }
    }
    return string(x[:])
}

func _trim(str, cutset string) string {
    var x string
    for {
        x = strings.Trim(str, cutset)
        if str == x {
            return str
        } else {
            str = x
        }
    }
}

func _replace(str, old, new string) string {
    var x string
    for {
        x = strings.Replace(str, old, new, -1)
        if str == x {
            return str
        } else {
            str = x
        }
    }
}