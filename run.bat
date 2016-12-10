CALL httpswatch -scangroup=NSDL
@ECHO ---------------------------------------------
CALL httpswatch -scangroup=IndianIncomeTaxFilingServices -createhostsfile=true
@ECHO ---------------------------------------------
CALL httpswatch -scangroup=IndianPharmacies -createhostsfile=true
@ECHO ---------------------------------------------
CALL httpswatch -scangroup=IndianBanksPublicSector -createhostsfile=true
@ECHO ---------------------------------------------
CALL httpswatch -scangroup=IndianBanksPrivateSector -createhostsfile=true
@ECHO ---------------------------------------------
CALL httpswatch -scangroup=IndianPaymentServices -createhostsfile=true
@ECHO ---------------------------------------------
PAUSE
