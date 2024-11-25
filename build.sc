// fmt: off
import mill._, scalalib._

object uniproxy extends ScalaModule {
  def scalaVersion = "3.5.2"
  def ivyDeps = Agg(
    // ivy"com.lihaoyi::scalatags:0.12.0",
    ivy"com.comcast::ip4s-core:3.6.0",
    ivy"com.lihaoyi::mainargs:0.6.2"
  )

  object test extends ScalaTests with TestModule.Munit {
    def ivyDeps = Agg(
      ivy"org.scalameta::munit::1.0.2"
    )
    // def testFramework = "utest.runner.Framework"
  }
  // testrunner

  def compileIvyDeps      = Agg(ivy"com.lihaoyi:::acyclic:0.3.15")
  def scalacPluginIvyDeps = Agg(ivy"com.lihaoyi:::acyclic:0.3.15")
  def scalacOptions       = Seq("-P:acyclic:force")

}
