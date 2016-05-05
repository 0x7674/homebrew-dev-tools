#!/usr/bin/env ruby

#
# Description: Check formulae for known vulnerabilities. Outputs
#              json by default.
#   --deptree for a verbose view of packages and their vulnerable
#             dependencies
#
#   --outfile to throw output into brew_vulnchecker_output.txt
#
# Author: 0x7674
# Usage:
#   brew vulnchecker [specific formulae] [--deptree] [--outfile]
#

require "formula"
require "ostruct"
require "set"
require "cgi"

begin
  require "nokogiri"
rescue LoadError
  puts "Homebrew does not provide Ruby dependencies; install with:"
  puts "  gem install nokogiri"
  odie "Dependency nokogiri is not installed."
end

trap("SIGINT") do
  puts "\nExiting..."
  exit!
end

class Vulnchecker
  CVE_URL = "https://www.cvedetails.com/version-search.php?product=".freeze

  def initialize
    formulae = []
    @vulns = {}
    output_buffer = ""

    if ARGV.empty?
      formulae = Formula
    else
      formulae = ARGV.formulae
      deps = Set.new
      if ARGV.include? "--deptree"
        formulae.each do |formula|
          deps.merge deps_for_formula(formula)
        end

        @vulns.merge! vuln_checker(deps)
      end
    end

    @vulns.merge!(vuln_checker(formulae))

    if ARGV.include? "--deptree"
      output_buffer = puts_deps_tree(formulae)
    else
      output_buffer = @vulns
    end

    if output_buffer.empty?
      output_buffer = "No vulnerabilities found."
    end

    if ARGV.include? "--outfile"
      File.open("brew_vulnchecker_output.txt", "w") { |f| f.write(output_buffer) }
    else
      puts output_buffer
    end
  end

  def get_cves(formula_name, formula_version)
    vulns = []
    html = Nokogiri::HTML(open("#{CVE_URL}#{formula_name}&version=#{formula_version}"))

    title = html.css("title").text
    if title == "Vendor, Product and Version Search"
      # There were more than one entries for that product name / version.
      # puts "[!] No exact match for #{pac_name}. Checking for other matches..."
      product_table = html.css("table.searchresults tr")[1..-1]

      vendor = ""
      max_vulns = 0

      product_table.each do |line|
        if line.text =~ /No matches/
          return vulns
        else
          product_vulns = line.css("td")[7].text.to_i

          if product_vulns > max_vulns
            max_vulns = product_vulns
            vendor = CGI.escape(line.css("td")[1].text.strip)
          end
        end
      end
      # puts "[+] Selected vendor #{vendor} for package #{formula_name}"

      html = Nokogiri::HTML(open("#{CVE_URL}#{formula_name}&version=#{formula_version}&vendor=#{vendor}"))
    end

    links = html.css("a")
    links.each do |link|
      vulns << link.text if link.text.include?("CVE-")
    end

    vulns
  end

  def puts_deps_tree(formulae)
    output_buffer = ""

    formulae.each do |f|
      unless @vulns[f.name].nil?
        output_buffer << "#{f.full_name} is vulnerable to: #{@vulns[f.name].join(" ")}\n"
      end

      output = recursive_deps_tree(f)
      if output[/CVE-/]
        output_buffer << "#{f.full_name} has one or more vulnerable dependencies:\n"
        output_buffer << output
      end
    end

    output_buffer
  end

  def deps_for_formula(f)
    ignores = []
    ignores << "build?" unless ARGV.include? "--include-build"
    ignores << "optional?" unless ARGV.include? "--include-optional"

    deps = f.recursive_dependencies do |dependent, dep|
      Dependency.prune if ignores.any? { |ignore| dep.send(ignore) } && !dependent.build.with?(dep)
    end

    dep_names = deps.map &:to_formula
    dep_names
  end

  def recursive_deps_tree(f, prefix = "")
    output = ""
    deps = f.deps.default
    max = deps.length - 1

    deps.each_with_index do |dep, i|
      chr = "└──"
      prefix_ext = i == max ? "    " : "│   "

      if !@vulns[dep.name].nil?
        output << prefix << "#{chr} #{dep.name} is vulnerable to: #{@vulns[dep.name].join(" ")}\n"
      else
        output << prefix << "#{chr} #{dep.name}\n"
      end

      tmp = recursive_deps_tree(Formulary.factory(dep.name), prefix + prefix_ext)
      if tmp[/CVE-/]
        output << tmp
      end
    end

    output
  end

  def vuln_checker(formulae)
    vuln_hash = {}

    formulae.each do |formula|
      next unless formula.stable
      formula_version = formula.stable.version

      ohai "Checking #{formula.full_name}..."

      begin
        vulns = get_cves(formula.name, formula_version)

        if vulns.any?
          vuln_hash[formula.full_name] = vulns
        end
      rescue Errno::EHOSTDOWN, Errno::ETIMEDOUT => e
        puts "[!] An error occurred while lookup up vulns for #{formula.full_name}: #{e}"
      end
    end

    vuln_hash
  end
end

Vulnchecker.new
