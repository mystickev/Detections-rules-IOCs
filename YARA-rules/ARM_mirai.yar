/*
	Mirai yara rule
	Author: ~mystik
	Date: 2023-08-30
	Identifier: Mirai
*/

rule MiraiAugust2023 {
	meta:
		Author = "Mystik_kev"
		Description = "Detects 2023 arm mirai sample"
		Reference = "Research"
		Date = "30-08-2023"
		hash = "b21de5eb1361f7719d225ec0604fb2ecf6c52a4a9bc5f3442058e81b5cc9db2b"
		
	strings:
		$ip1 = "176.123.2.148"
		$ip2 = "192.168.0.14:80"
		
		$s1 = "./nig realtek"
		$s2 = "POST /picdesc.xml"
		$s3 = "echo HUAWEIUPNP"
		$s4 = "/bin/busybox chmod 777"
		$s5 = "POST /wanipcn.xml"
		$s6 = "wget http://176.123.2.148/"
		$s7 = "FederalSocialv4.mips"
	
	condition:
		uint32(0) == 0x464c457f and filesize < 100KB and
		(
			(1 of ($ip*) and 1 of ($s*) ) or 5 of ($s*)
		)
	
}

