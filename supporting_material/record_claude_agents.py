"""Record the 40 Claude-subagent responses (received 2026-10-21) as raw output.

Source: each subagent's final hand-back message, as delivered by the Claude Code harness to the
orchestrating session. The harness indents report lines by two spaces; that indentation is the
only thing removed. The per-agent transcript files were empty (0 bytes) in this environment, so
these hand-back texts are the most primitive record available (see limitations.md).
Mapping agent-launch -> (sample, condition) follows the launch order in the orchestrating session.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
R = {}
R[("S01", "basic")] = '{"label": "Vulnerable"}'
R[("S01", "structured")] = """Untrusted input: the `name` request parameter is the only external input. Data flow: it is trimmed and passed to `IO.writeLine`, a console/stdout writer, not the HTTP response. The `HttpServletResponse` is never used. Controls: none are needed because the value never reaches a sensitive sink (no SQL, OS command, file path, response body or header). A missing parameter would cause a null-pointer exception, which is a robustness bug and not an exploitable vulnerability. Evidence: nothing shows untrusted data reaching a dangerous operation. Label: Safe.

{"label": "Safe"}"""
R[("S02", "basic")] = '{"label": "Safe"}'
R[("S02", "structured")] = """1. Untrusted inputs: none. The request object is never read. The only value, `data`, is the hardcoded constant "foo".
2. Data flow: `data` is the constant "foo". It goes into the HTML output through `response.getWriter().println`, inside an img src attribute.
3. Security controls: none are applied, but none are needed. No attacker-controlled data reaches the output.
4. Evidence: the sink is an XSS-style sink, but its source is a constant. Nothing in the code shows untrusted data reaching it, so there is no exploitable flaw.
5. Classification: Safe.

{"label": "Safe"}"""
R[("S03", "basic")] = '{"label": "Vulnerable"}'
R[("S03", "structured")] = """1. Untrusted input: the request parameter "name" (`request.getParameter("name")`).
2. Data flow: `data` is concatenated into an HTML string, `<img src="...">`, and written to the response with `response.getWriter().println`. Nothing sits between the input and the output.
3. Controls: there is no HTML encoding, quote escaping or validation. The only check is `data != null`, which is not a security control. A value such as `" onerror="alert(1)` breaks out of the src attribute. A value containing `">` can inject arbitrary tags.
4. Evidence: untrusted data reaches an HTML response unsanitized, so the code is open to reflected cross-site scripting (XSS, CWE-79).
5. Classification: Vulnerable.

{"label": "Vulnerable"}"""
R[("S04", "basic")] = '{"label": "Safe"}'
R[("S04", "structured")] = """1. Untrusted input: request.getParameter("name"), a user-controlled string.

2. Data flow: The string goes to Integer.parseInt. If parsing fails, numberOfLoops is set to 1. The value then controls a loop that writes "hello world" through IO.writeLine. The user's string is never written out.

3. Controls: The loop only runs if numberOfLoops is between 0 and 5, so an attacker cannot force a large loop and cause resource exhaustion. The input is not used in SQL, commands, file paths or HTTP output. A null parameter makes parseInt throw NumberFormatException, which is caught.

4. Evidence: No untrusted data reaches a sensitive operation without a control. The bounds check removes the uncontrolled-loop risk.

5. Classification: Safe.

{"label": "Safe"}"""
R[("S05", "basic")] = '{"label": "Vulnerable"}'
R[("S05", "structured")] = """Step 1: The untrusted input is the request parameter "name".

Step 2: The value is split with `split("||")`. In regex, `||` matches the empty string, so the split yields single characters. This affects parsing, not security. The first two characters become `username` and `password`. They are concatenated directly into an XPath query string, and `xPath.evaluate` runs that query.

Step 3: No escaping, parameterization, or validation is applied to `username` or `password`. `StringEscapeUtils` is imported but never used. Because the split produces single characters, an attacker can supply a quote character as a token, which breaks out of the string literal. The query construction is still XPath injection, since attacker-controlled characters reach the query unsanitized.

Step 4: Untrusted data reaches the XPath evaluation with no control. This is the classic CWE-643 XPath injection pattern.

Step 5: Vulnerable.

{"label": "Vulnerable"}"""
R[("S06", "basic")] = '{"label": "Safe"}'
R[("S06", "structured")] = """1. Untrusted inputs: the request and response parameters are never read. The only value is data = "foo", a hardcoded constant.
2. Data flow: the constant goes into new URI(data) and then response.sendRedirect(data). No external data reaches the redirect.
3. Controls: the constant is parsed as a URI and the result is not used. That check is irrelevant, because no user input is involved.
4. Evidence: an attacker cannot influence the redirect target, so there is no open redirect. sendRedirect is dangerous only when its argument is tainted, and here it is not.
5. Classification: Safe.

{"label": "Safe"}"""
R[("S07", "basic")] = '{"label": "Safe"}'
R[("S07", "structured")] = """Safe. The only untrusted input is the request parameter "name". Both tokens pass through StringEscapeUtils.escapeXml before being concatenated into the XPath query, and that escapes ' and ". An attacker therefore can't break out of the quoted XPath literal. The split on "||" is an empty-alternation regex, so each token is a single character, which leaves even less room for injection. The XML file path is fixed, not user-controlled.

{"label": "Safe"}"""
R[("S08", "basic")] = '{"label": "Vulnerable"}'
R[("S08", "structured")] = """Step 1: The untrusted input is the request parameter "name".

Step 2: The value flows into `response.getWriter().println(...)`, an HTML response.

Step 3: The only control is `replaceAll("(<script>)", "")`, which removes the literal lowercase `<script>` tag.
- It is case-sensitive, so `<SCRIPT>` passes through.
- It does not remove other vectors such as `<img src=x onerror=alert(1)>` or `<svg onload=...>`.
- It is easy to bypass with nesting, for example `<scr<script>ipt>`, which becomes `<script>` after the removal.
- It does no HTML encoding.

Step 4: Untrusted data reaches the HTML output without adequate encoding or sanitization, so reflected XSS is possible.

Step 5: Vulnerable.

{"label": "Vulnerable"}"""
R[("S09", "basic")] = '{"label": "Safe"}'
R[("S09", "structured")] = """Step 1: The untrusted input is the request parameter "name".

Step 2: The value flows into the "Location" response header, which is a sensitive sink for header injection and open redirect.

Step 3: `URLEncoder.encode` percent-encodes CR, LF and other special characters, so the value can't inject new headers or split the response. The value is appended to a fixed relative path, "/author.jsp?lang=", and only as a query parameter. The attacker therefore can't control the redirect destination.

Step 4: No untrusted data reaches the sensitive operation without an adequate control.

Step 5: Safe.

{"label": "Safe"}"""
R[("S10", "basic")] = '{"label": "Vulnerable"}'
R[("S10", "structured")] = """Step 1: The untrusted input is the request parameter "name".

Step 2: The value is parsed with `new URI(data)` and then passed unchanged to `response.sendRedirect(data)`.

Step 3: The only control is the `URI` syntax check. It rejects malformed strings. It doesn't restrict the scheme or host, so absolute URLs such as `http://evil.com` pass. It also doesn't check against an allowlist or require a relative path.

Step 4: An attacker can supply any well-formed URL and cause the server to redirect users to it. This is an open redirect (CWE-601), and no adequate control stops it.

Step 5: Vulnerable.

{"label": "Vulnerable"}"""
R[("S11", "basic")] = '{"label": "Vulnerable"}'
R[("S11", "structured")] = """1. Untrusted input: the request parameter "name" (`request.getParameter("name")`).

2. Data flow: the value goes straight into `new File(data)`. If the file exists and is a regular file, the code opens it with `FileInputStream`, reads the first line, and writes that line out with `IO.writeLine`.

3. Controls: the only checks are `data != null` and `file.exists() && file.isFile()`. These test the file's state. They do not restrict the path to a base directory, canonicalize it, or filter `../` sequences and absolute paths.

4. Evidence: an attacker can supply a path such as `/etc/passwd` or `../../secret`. That path is opened, and the first line of the file is returned to the caller through the output sink. This is path traversal and arbitrary file read, and nothing in the code prevents it.

5. Classification: Vulnerable (CWE-22 / CWE-23).

{"label": "Vulnerable"}"""
R[("S12", "basic")] = '{"label": "Vulnerable"}'
R[("S12", "structured")] = """1. Untrusted input: the request parameter "name", read into `data`.
2. Data flow: `data` is concatenated into "/author.jsp?lang=" + data. The result is set as the value of the "Location" response header with `response.setHeader`.
3. Security controls: the only check is a null check. The value is not URL-encoded (URLEncoder is imported but never used). CR and LF characters are not stripped. No allow-list is applied.
4. Evidence: an attacker can put CRLF sequences in `name` to inject extra headers or split the response (HTTP response splitting, CWE-113). Many modern containers filter CR/LF in header values, but the code itself has no control. It also allows parameter injection into the redirect URL.
5. Classification: Vulnerable.

{"label": "Vulnerable"}"""
R[("S13", "basic")] = '{"label": "Safe"}'
R[("S13", "structured")] = """1. Untrusted inputs: The method receives request and response, but it never reads them. The only value that matters is `data`, which is the hardcoded literal "foo".
2. Data flow: "foo" goes into `new File(data)`, then into a FileInputStream, and the first line is written out. No external input reaches the file path.
3. Security controls: There are none, but none are needed because the path is constant. The code also checks that the file exists and is a regular file.
4. Evidence: An attacker cannot influence the path, so there is no path traversal or arbitrary file read. This looks like the "good" variant of a CWE-23/36 test case.
5. Classification: Safe.

{"label": "Safe"}"""
R[("S14", "basic")] = '{"label": "Vulnerable"}'
R[("S14", "structured")] = """1. Untrusted input: `request.getParameter("name")` is attacker-controlled.
2. Data flow: the value goes through `Integer.parseInt` into `numberOfLoops`. That value is the loop bound for the `for` loop that calls `IO.writeLine`.
3. Controls: the code only handles `NumberFormatException`, falling back to 1. It does not check the range, so a value like 2000000000 is accepted. Negative values just skip the loop.
4. Evidence: an attacker can set the iteration count arbitrarily. Each iteration does I/O, so a large value ties up CPU and fills the logs or output. That is resource exhaustion (CWE-606/CWE-400, unchecked input for loop condition).
5. Classification: Vulnerable.

{"label": "Vulnerable"}"""
R[("S15", "basic")] = '{"label": "Safe"}'
R[("S15", "structured")] = """1. Untrusted input: the request parameter "name", read with request.getParameter.
2. Data flow: the value is trimmed and passed to IO.writeLine. In the Juliet test suite, which this code looks like, IO.writeLine writes to the console or a log. It does not write to the HTTP response, a database, an OS command or a file path.
3. Controls: trim() is not a security control. The sink does not need one, because the data never reaches an HTML response, SQL, a command or a file operation.
4. Evidence: nothing here shows untrusted data reaching a dangerous sink. A log or console write alone is not an exploitable vulnerability in this snippet. The code is in the style of a Juliet "good" or neutral case that only reads input and prints it.
5. Classification: Safe.

{"label": "Safe"}"""
R[("S16", "basic")] = '{"label": "Vulnerable"}'
R[("S16", "structured")] = """1. Untrusted inputs: none. The `request` parameter is never read. `data` is the hardcoded constant "foo".
2. Data flow: "foo" goes through `replaceAll` and into `response.getWriter().println`, which is an HTML response sink.
3. Security controls: the `replaceAll` call strips `<script>` and would be a weak filter. It isn't needed here, because the data is a constant.
4. Evidence: no externally controlled data reaches the sink, so XSS can't happen. The API alone doesn't make the code vulnerable.
5. Classification: Safe.

{"label": "Safe"}"""
R[("S17", "basic")] = '{"label": "Vulnerable"}'
R[("S17", "structured")] = """1. Untrusted input: the request parameter "name" (`request.getParameter("name")`). It is split on "-" into `names[]`.
2. Data flow: each `names[i]` is concatenated directly into the SQL string `"update users set hitcount=hitcount+1 where name='" + names[i] + "'"`. That string is passed to `Statement.addBatch` and run with `executeBatch`.
3. Controls: there is no parameterization (no PreparedStatement), escaping or validation. Splitting on "-" only blocks the hyphen character. An attacker can still inject with a single quote and other SQL syntax, for example `x' or '1'='1`. Comments can be written without a hyphen, such as `#` on MySQL or `/* */`.
4. Evidence: untrusted data reaches a SQL execution sink through string concatenation with no adequate control. This is SQL injection.
5. Classification: Vulnerable.

{"label": "Vulnerable"}"""
R[("S18", "basic")] = '{"label": "Safe"}'
R[("S18", "structured")] = """Step 1: The untrusted input is the `name` request parameter, which is split on "-" into `names`.

Step 2: Each element of `names` goes into a `PreparedStatement` through `setString(1, ...)`. The SQL text is a constant: "update users set hitcount=hitcount+1 where name=?".

Step 3: Parameter binding keeps the input as data, so SQL injection is not possible. The only output is `IO.writeLine`, which prints counts and the array length. It does not echo the input, so there is no XSS or injection through the output. The exceptions are logged but not shown to the user.

Step 4: No untrusted data reaches a sensitive operation without a control.

Step 5: Safe.

{"label": "Safe"}"""
R[("S19", "basic")] = '{"label": "Safe"}'
R[("S19", "structured")] = """Step 1: The method receives request and response objects, but neither is read. No external input is used.

Step 2: `data` is hardcoded to "foo". The command string is `osCommand + data`, where `osCommand` depends only on the `os.name` system property. That value is not controlled by an attacker.

Step 3: No tainted data reaches `Runtime.exec`, so no control is needed.

Step 4: `exec` is a dangerous API, but the argument is a constant. An attacker cannot influence the command, so there is no evidence of command injection.

Step 5: Safe.

{"label": "Safe"}"""
R[("S20", "basic")] = '{"label": "Vulnerable"}'
R[("S20", "structured")] = """1. Untrusted input: `request.getParameter("name")` is attacker-controlled.
2. Data flow: `data` is concatenated directly onto the OS command string (`"/bin/ls " + data` or `cmd.exe /c dir ` + data) and passed to `Runtime.getRuntime().exec(String)`.
3. Controls: There is no validation, sanitization or whitelisting. `exec(String)` splits the string on whitespace, so the attacker can inject extra arguments. On Windows, `cmd.exe /c` also allows metacharacters like `&` to chain commands. On Linux, the injected arguments can still change what `ls` does, such as reading arbitrary paths or using option flags.
4. Evidence: Untrusted data reaches command execution with no control, which is OS command injection (CWE-78).
5. Classification: Vulnerable.

{"label": "Vulnerable"}"""

assert len(R) == 40
prompts = {(p["sample_id"], p["condition"]): p["prompt_sha256"]
           for p in map(json.loads, open(HERE / "results" / "agent_prompts.jsonl", encoding="utf-8"))}
out = HERE / "results" / "raw" / "claude_agents.jsonl"
out.parent.mkdir(parents=True, exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    for (sid, cond), text in sorted(R.items()):
        f.write(json.dumps({"run_id": "claude_agents", "model": "Claude Sonnet via Claude Code subagent (alias 'sonnet')",
                            "condition": cond, "sample_id": sid,
                            "timestamp_utc": "2026-10-21 (session date; per-call time not exposed)",
                            "prompt_sha256": prompts[(sid, cond)], "error": "", "response": text,
                            "capture": "subagent hand-back text; harness 2-space indent removed"},
                           ensure_ascii=False) + "\n")
print("wrote", out)
