// Host-side check that tools/tapout (the signer) and tapout/cmd_proto.h (the
// device's parser/verifier + topic-URL guards) agree. Run via tools/test_cmd_proto.sh.
//
// Records on stdin, one per line:
//   <expect> <pubkey.pem> <line>  parse+verify; expect OK or an error name
//   URL <ok|bad> <url>        cmdUrlLooksOk()
//   SAME <yes|no> <a> <b>     cmdSameTopic()
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <iterator>
#include "../tapout/cmd_proto.h"

static const char* errName(int e) {
  switch (e) {
    case CMD_OK: return "OK";
    case CMD_ERR_FORMAT: return "FORMAT";
    case CMD_ERR_TOO_LONG: return "TOO_LONG";
    case CMD_ERR_NO_SIG: return "NO_SIG";
    case CMD_ERR_BAD_SIG: return "BAD_SIG";
    case CMD_ERR_MISSING: return "MISSING";
    case CMD_ERR_NO_KEY: return "NO_KEY";
  }
  return "?";
}

int main() {
  std::string rec;
  int fails = 0, n = 0;
  while (std::getline(std::cin, rec)) {
    if (rec.empty()) continue;
    size_t a = rec.find(' '), b = rec.find(' ', a + 1);
    std::string kind = rec.substr(0, a), f1 = rec.substr(a + 1, b - a - 1), rest = rec.substr(b + 1);
    bool pass;
    n++;
    if (kind == "URL") {
      bool ok = cmdUrlLooksOk(rest.c_str());
      pass = ok == (f1 == "ok");
      printf("%s  url  expect=%-4s got=%-4s %s\n", pass ? "PASS" : "FAIL", f1.c_str(), ok ? "ok" : "bad", rest.c_str());
    } else if (kind == "SAME") {
      size_t c = rest.find(' ');
      std::string x = rest.substr(0, c), y = rest.substr(c + 1);
      bool same = cmdSameTopic(x.c_str(), y.c_str());
      pass = same == (f1 == "yes");
      printf("%s  same expect=%-4s got=%-4s %s == %s\n", pass ? "PASS" : "FAIL", f1.c_str(), same ? "yes" : "no",
             x.c_str(), y.c_str());
    } else {
      // f1 is a path to the PUBLIC key PEM the "device" verifies against.
      std::ifstream kf(f1);
      std::string pem((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
      CmdMsg m;
      int e = cmdParseVerify(rest.c_str(), rest.size(), pem.c_str(), &m);
      pass = kind == errName(e);
      printf("%s  cmd  expect=%-8s got=%-8s", pass ? "PASS" : "FAIL", kind.c_str(), errName(e));
      if (e == CMD_OK)
        printf("  c=%s to=%s m=%u p=%s w=%s u=[%s] ti=[%s] b=[%s]", m.c, m.to, m.m, m.p, m.w, m.u, m.ti, m.b);
      printf("\n");
    }
    if (!pass) fails++;
  }
  printf("%d/%d passed\n", n - fails, n);
  return fails ? 1 : 0;
}
