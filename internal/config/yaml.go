package config

import (
	"fmt"
	"strings"
)

// parseYAML 解析本项目配置所需的 YAML 子集：
//
//   - 任意层级的嵌套映射（按缩进识别层级，只允许空格缩进，不允许 Tab）；
//   - 标量值：裸标量与双引号字符串；
//   - "#" 行注释与值后的行内注释（行内注释仅在不处于引号内时生效）；
//   - 不支持列表、锚点、多行字符串、流式集合等语法。
//
// 返回 map[string]any，其中嵌套映射的值类型为 map[string]any，
// 标量一律以 string 表示（类型转换由上层 decode 函数完成）。
func parseYAML(data []byte) (map[string]any, error) {
	root := map[string]any{}
	// 栈元素：当前层缩进与所在 map。栈底是 root。
	type frame struct {
		indent int
		m      map[string]any
	}
	stack := []frame{{indent: -1, m: root}}

	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		content := stripComment(line)
		if strings.TrimSpace(content) == "" {
			continue
		}
		indent := 0
		for indent < len(content) && content[indent] == ' ' {
			indent++
		}
		if indent < len(content) && content[indent] == '\t' {
			return nil, fmt.Errorf("line %d: tab indentation is not supported", lineNo+1)
		}
		body := strings.TrimSpace(content[indent:])
		if body == "" {
			continue
		}

		key, rest, err := splitKeyValue(body, lineNo+1)
		if err != nil {
			return nil, err
		}

		// 回退栈到缩入不高于当前行的层。
		for len(stack) > 1 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].m

		if rest == "" {
			// "key:" 开启子映射。
			child := map[string]any{}
			parent[key] = child
			stack = append(stack, frame{indent: indent, m: child})
			continue
		}

		parent[key] = unquote(strings.TrimSpace(rest))
	}

	return root, nil
}

// splitKeyValue 拆分 "key: value" 或 "key:"。
// 键可以是双引号包裹的形式（如 "0.0.0.0:30000"），
// 此定位以闭合引号为界，键内的冒号不影响解析。
func splitKeyValue(body string, lineNo int) (key, value string, err error) {
	if strings.HasPrefix(body, `"`) {
		end := strings.Index(body[1:], `"`)
		if end < 0 {
			return "", "", fmt.Errorf("line %d: unterminated quoted key", lineNo)
		}
		key = body[1 : 1+end]
		if key == "" {
			return "", "", fmt.Errorf("line %d: empty key", lineNo)
		}
		rest := body[1+end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("line %d: expected ':' after quoted key", lineNo)
		}
		return key, rest[1:], nil
	}

	idx := strings.Index(body, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("line %d: expected \"key: value\", got %q", lineNo, body)
	}
	key = strings.TrimSpace(body[:idx])
	if key == "" {
		return "", "", fmt.Errorf("line %d: empty key", lineNo)
	}
	return key, body[idx+1:], nil
}

// stripComment 去掉行注释，考虑双引号内的 '#'。
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}

// unquote 若 s 是完整双引号字符串则去引号，否则原样返回。
func unquote(s string) string {
	if v, ok := tryUnquote(s); ok {
		return v
	}
	return s
}

func tryUnquote(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s, false
	}
	inner := s[1 : len(s)-1]
	// 引号内不允许再出现未转义的引号（本配置语法足够简单）。
	if strings.Contains(inner, `"`) {
		return s, false
	}
	return inner, true
}
