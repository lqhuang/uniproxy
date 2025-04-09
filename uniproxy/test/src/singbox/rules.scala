import uniproxy.singbox.route.Rule

class RuleTests extends munit.FunSuite:

  test("hello") {
    val rule = Rule(outbound = "direct", domain = Some("google.com"))

    assertEquals(rule.outbound, "direct")
  }
