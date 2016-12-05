---
layout: blank
---
<div>
	<h2>{{ site.title }}</h2>
</div>
<hr>
<div>
	This project aims to create an actionable dashboard listing the TLS configurations of certain websites where good security in transit is expected.
	This uses the <a href="https://www.ssllabs.com/ssltest/index.html">Qualys SSL Labs Server Test</a> to evaluate a site's TLS configuration and displays its grade. Issues with a site's TLS configuration that
	prevent it from obtaining an 'A' grade or better are highlighted. The full report is also available via a hyperlink to the Qualys site.
	<br><br>
	At this time, the focus is on websites used by services in India. In my opinion, most internet users in India do not understand or underestimate the importance of online privacy and security and this is reflected
	in the sorry state of HTTPS adoption and deployment, especially for government agencies. While my request to mandate the use of HTTPS hasn't been acknowledged by the agency responsible for
	maintaining government websites, my hope is that with enough exposure they will do something similar to what has been done by <a href="https://https.cio.gov/">the USA for websites operated by the Federal Government</a> and <a href="https://www.ncsc.gov.uk/guidance/tls-external-facing-services">the UK</a>.
	<br><br>
	Most people historically associate HTTPS with things that need to be kept private, like login information or a page that accepts payment details but it is becoming increasingly clear that all web properties need to use HTTPS to ensure a safe and secure web experience. An excellent write-up for "HTTPS Everywhere" can be found at the aforementioned <a href="https://https.cio.gov/everything/">US Federal Government's
	"HTTPS-Only Standard" site</a>.
	<br><br>
	The reason for including subdomains not normally used by the general public is that these are typically not maintained at the same standard as the main domain. Some of these (such as vpn.domain.com, 
	webmail.domain.com etc.) are used by employees to access internal resources and it is imperative that these be protected at the same level, if not better, than a site that is used by the general public.
	Having poor transport layer security on such sites could lead to the an employee's credentials being compromised which could give an attacker access to internal systems. Then there are subdomains that continue to
	be vulnerable to serious veulnerabilies such as <a href="https://en.wikipedia.org/wiki/Heartbleed">Heartbleed</a> that can be a great asset to attackers.
	<br><br>
	The subdomains considered for the tests here were discovered using a combination of Google searches (using the <i>site</i> operator), VirusTotal
	(<i>https://virustotal.com/en/domain/{domain.com}/information/</i>) and <a href="https://dnsdumpster.com/">DNSDumspter</a>.
</div>
<hr>
<div>
	<h4>Categories:</h4>
	<ul>
		<li><a href="./reports/indianPharmacies">Indian Pharmacies</a> - Online pharmacies in India. Most, if not all, require a patient's details along with prescriptions when filling out an order.</li>
		<li><a href="./reports/indianIncomeTaxFilingServices">Indian Income Tax Filing Services</a> - Income Tax Filing Services in India</li>
		<li>Indian Banks:
			<ul>
				<li><a href="./reports/indianBanksPublicSector">Public sector</a> - Public sector banks in India.</li>
				<li><a href="./reports/indianBanksPrivateSector">Private sector</a> - Private sector banks in India.</li>
			</ul>
		</li>
		<li>To do: Payment services (10% complete)</li>
		<li>Securities and trading:
			<ul>
				<li><a href="./reports/nsdl">NSDL</a> - NSDL is the depository for the equity market in India.</li>
			</ul>
		</li>
	</ul>
</div>