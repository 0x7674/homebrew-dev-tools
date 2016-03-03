# encoding: UTF-8
require "formula"
require "Nokogiri"
require "ostruct"
require "set"


class Vulnchecker
  CVE_URL = "https://www.cvedetails.com/version-search.php?product="

  def initialize
    formulae = []
    @vulns = {}

    if ARGV.empty?
      formulae = Formula
    else
      formulae = ARGV.formulae
      deps = Set.new
      formulae.each do |formula|
        deps.merge deps_for_formula(formula)
      end
      
      @vulns.merge! vuln_checker(deps)
    end

    @vulns.merge!(vuln_checker formulae)
    puts_deps_tree(formulae)
  end

  def get_cves(formula_name, formula_version)
    vulns = []
    html = Nokogiri::HTML(open("#{CVE_URL}#{formula_name}&version=#{formula_version}"))
    
    title = html.css("title").text
    if title == "Vendor, Product and Version Search"
      # There were more than one entries for that product name / version.
      #puts "[!] No exact match for #{pac_name}. Checking for other matches.."
      product_table = html.css("table.searchresults tr")[1..-1]
        
      vendor = ""
      max_vulns = 0
        
      product_table.each do |line|
        if line.text.match "No matches"
          return vulns
        else
          product_vulns = line.css("td")[7].text.to_i

          if product_vulns > max_vulns
            max_vulns = product_vulns
            vendor = line.css("td")[1].text.strip
          end
        end
      end
      #puts "[+] Selected vendor #{vendor} for package #{formula_name}"

      html = Nokogiri::HTML(open("#{@CVE_URL}#{formula_name}&version=#{formula_version}&vendor=#{vendor}"))
    end

    links = html.css("a")
    links.each do |link|
        vulns << link.text if link.text.include?("CVE-")
    end

    vulns

  end

  def puts_deps_tree(formulae)
    formulae.each do |f|
      unless @vulns[f.name].nil?
        puts "#{f.full_name} is vulnerable to: #{@vulns[f.name].join(' ')}\n"
      end

      output = recursive_deps_tree(f)
      if output[/CVE-/]
        puts "#{f.full_name} has one or more vulnerable dependencies:"
        puts output
      end

    end
  end

  def deps_for_formula(f)
    ignores = []
    ignores << "build?" unless ARGV.include? "--include-build"
    ignores << "optional?" unless ARGV.include? "--include-optional"
    dep_names = []

    deps = f.recursive_dependencies do |dependent, dep|
      Dependency.prune if ignores.any? { |ignore| dep.send(ignore) } && !dependent.build.with?(dep)
    end

    dep_names = deps.map { |dep| dep.to_formula }
    dep_names
  end


  def recursive_deps_tree(f, prefix="")
    output = ""
    deps = f.deps.default
    max = deps.length - 1

    deps.each_with_index do |dep, i|
      chr = "└──"
      prefix_ext = i == max ? "    " : "│   "

      unless @vulns[dep.name].nil?
        output << prefix << "#{chr} #{dep.name} is vulnerable to: #{@vulns[dep.name].join(' ')}\n"
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

      ohai "Checking #{formula.full_name}.."

      begin 
        vulns = get_cves(formula.name, formula_version)
              
        if vulns.any?
          vuln_hash[formula.full_name] = vulns
        end
      rescue Exception=>e # get the right exception class
        puts "[!] An error occurred while lookup up vulns for #{formula.full_name}: #{e}"
      end
    end

    vuln_hash
  end
end

Vulnchecker.new
