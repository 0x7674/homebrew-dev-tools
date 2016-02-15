# encoding: UTF-8
require "formula"
require "Nokogiri"
require "ostruct"

module Homebrew

  class Vulnchecker
    def initialize
      @vulns = vuln_checker Formula
      puts_deps_tree(Formula)
    end

    def get_cves(cve_url, pac_name, pac_ver)
      vulns = Array.new
      html = Nokogiri::HTML(open("#{cve_url}#{pac_name}&version=#{pac_ver}"))
      
      title = html.css("title").text
      if title == "Vendor, Product and Version Search"
        # There were more than one entries for that product name / version.
        #puts "[!] No exact match for #{pac_name}. Checking for other matches.."
        product_table = html.css("table.searchresults tr")[1..-1]
          
        vendor = String.new
        max_vulns = 0
          
        product_table.each do |line|
          if line.text.match("No matches")
            #puts "[-] No matches found"
            return vulns
          else
            product_vulns = line.css("td")[7].text.to_i
  
            if product_vulns > max_vulns
              max_vulns = product_vulns
              vendor = line.css("td")[1].text.lstrip.rstrip
            end
          end
        end
        #puts "[+] Selected vendor #{vendor} for package #{pac_name}"
  
        html = Nokogiri::HTML(open("#{cve_url}#{pac_name}&version=#{pac_ver}&vendor=#{vendor}"))
      end
  
  
      links = html.css("a")
      links.each do |link|
        if link.text.match("CVE-")
          vulns.push(link.text)
        end
      end
  
      return vulns
  
    end

    def puts_deps_tree(formulae)
      formulae.each do |f|
        if !@vulns[f.name].nil?
          puts "#{f.full_name} is vulnerable to: #{@vulns[f.name].join(' ')}\n"
        end

        output = recursive_deps_tree(f, "")
        if output[/CVE-/]
          puts "#{f.full_name} has one or more vulnerable dependencies:"
          puts output
        end

      end
    end

    def recursive_deps_tree(f, prefix)
      output = String.new
      deps = f.deps.default
      max = deps.length - 1

      deps.each_with_index do |dep, i|
      
        chr = "└──"
        prefix_ext = i == max ? "    " : "│   "

        if !@vulns[dep.name].nil?
          output << prefix + "#{chr} #{dep.name} is vulnerable to: #{@vulns[dep.name].join(' ')}\n"
        else
          output << prefix + "#{chr} #{dep.name}\n"
        end

        tmp = recursive_deps_tree(Formulary.factory(dep.name), prefix + prefix_ext)
        if tmp[/CVE-/]
          output << tmp
        end
      end
    
      return output
    end

    def vuln_checker(formulae)
      cve_url = "https://www.cvedetails.com/version-search.php?product="

      vuln_hash = Hash.new

      formulae.each do |formula|

        formula_name = formula.name
        formula_vers = formula.stable.version

        puts "Checking #{formula_name}.."

        begin 
          vulns = get_cves(cve_url, formula_name, formula_vers)
                
          if !vulns.empty?
            vuln_hash[formula_name] = Array.new
            vuln_hash[formula_name].push(vulns)
          end
        rescue Exception=>e
          puts %{[!] An error occurred while lookup up vulns for #{formula_name}: #{e}}
        end
      end

      return vuln_hash
    end
  end

  def vulnchecker
    Vulnchecker.new
  end

end
