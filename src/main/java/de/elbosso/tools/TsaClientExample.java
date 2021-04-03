package de.elbosso.tools;

import java.io.IOException;

/*
Copyright (c) 2021.

Juergen Key. Alle Rechte vorbehalten.

Weiterverbreitung und Verwendung in nichtkompilierter oder kompilierter Form,
mit oder ohne Veraenderung, sind unter den folgenden Bedingungen zulaessig:

   1. Weiterverbreitete nichtkompilierte Exemplare muessen das obige Copyright,
die Liste der Bedingungen und den folgenden Haftungsausschluss im Quelltext
enthalten.
   2. Weiterverbreitete kompilierte Exemplare muessen das obige Copyright,
die Liste der Bedingungen und den folgenden Haftungsausschluss in der
Dokumentation und/oder anderen Materialien, die mit dem Exemplar verbreitet
werden, enthalten.
   3. Weder der Name des Autors noch die Namen der Beitragsleistenden
duerfen zum Kennzeichnen oder Bewerben von Produkten, die von dieser Software
abgeleitet wurden, ohne spezielle vorherige schriftliche Genehmigung verwendet
werden.

DIESE SOFTWARE WIRD VOM AUTOR UND DEN BEITRAGSLEISTENDEN OHNE
JEGLICHE SPEZIELLE ODER IMPLIZIERTE GARANTIEN ZUR VERFUEGUNG GESTELLT, DIE
UNTER ANDEREM EINSCHLIESSEN: DIE IMPLIZIERTE GARANTIE DER VERWENDBARKEIT DER
SOFTWARE FUER EINEN BESTIMMTEN ZWECK. AUF KEINEN FALL IST DER AUTOR
ODER DIE BEITRAGSLEISTENDEN FUER IRGENDWELCHE DIREKTEN, INDIREKTEN,
ZUFAELLIGEN, SPEZIELLEN, BEISPIELHAFTEN ODER FOLGENDEN SCHAEDEN (UNTER ANDEREM
VERSCHAFFEN VON ERSATZGUETERN ODER -DIENSTLEISTUNGEN; EINSCHRAENKUNG DER
NUTZUNGSFAEHIGKEIT; VERLUST VON NUTZUNGSFAEHIGKEIT; DATEN; PROFIT ODER
GESCHAEFTSUNTERBRECHUNG), WIE AUCH IMMER VERURSACHT UND UNTER WELCHER
VERPFLICHTUNG AUCH IMMER, OB IN VERTRAG, STRIKTER VERPFLICHTUNG ODER
UNERLAUBTE HANDLUNG (INKLUSIVE FAHRLAESSIGKEIT) VERANTWORTLICH, AUF WELCHEM
WEG SIE AUCH IMMER DURCH DIE BENUTZUNG DIESER SOFTWARE ENTSTANDEN SIND, SOGAR,
WENN SIE AUF DIE MOEGLICHKEIT EINES SOLCHEN SCHADENS HINGEWIESEN WORDEN SIND.
 */
public class TsaClientExample extends java.lang.Object
{
	public static void main(java.lang.String[] args) throws IOException
	{
		de.elbosso.util.Utilities.configureBasicStdoutLogging(org.apache.log4j.Level.TRACE);
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		java.io.File f=java.io.File.createTempFile("rfc3161test",".dat");
		System.out.println(f);
		f.deleteOnExit();
		try
		{
			byte[] timestampQuery = TsaClientHelper.makeQuery(f.toURI().toURL(), true, "0.4.0.2023.1.1");
			java.lang.String server="http://rfc3161timestampingserver.pi-docker.lab";
			byte[] timestampResponse= de.elbosso.util.security.TsaClientHelper.getResponse(timestampQuery,server);
			//would throw exception if verification would fail!
			TsaClientHelper.verify(f.toURI().toURL(),timestampResponse,new java.net.URL(server+"/chain.pem"));
		}
		catch(Throwable t)
		{
			t.printStackTrace();
		}
	}
}