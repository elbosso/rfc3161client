package de.elbosso.tools;

import org.slf4j.event.Level;

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
		de.elbosso.util.Utilities.configureBasicStdoutLogging(Level.ERROR);
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		java.io.File f=java.io.File.createTempFile("rfc3161test",".dat");
		java.io.PrintWriter pw=new java.io.PrintWriter(f);
		pw.println("huhu");
		pw.close();
		java.io.File fi=java.io.File.createTempFile("rfc3161test_invalid",".dat");
		pw=new java.io.PrintWriter(fi);
		pw.println("hallo");
		pw.close();
		System.out.println(f);
		f.deleteOnExit();
		try
		{
			byte[] timestampQuery = de.elbosso.util.security.TsaClientHelper.makeQuery(f.toURI().toURL(), true, "0.4.0.2023.1.1");
			java.lang.String server="http://rfc3161timestampingserver.pi-docker.lab";
			//java.lang.String server="http://timestamp.entrust.net/TSS/RFC3161sha2TS";
			//java.lang.String server="https://freetsa.org/tsr";
			byte[] timestampResponse= de.elbosso.util.security.TsaClientHelper.getResponse(timestampQuery,server);
			//would throw exception if verification would fail!

			//The third parameter is only needed if the tsa certificate is issued ba a CA that is not
			//yet in the JREs truststore - in that case, it holds the CAs the user deems trustworthy
			//TsaClientHelper.verify(f.toURI().toURL(),timestampResponse,new java.net.URL(server+"/chain.pem"));
			//to check the timestamp and make it fail - just use a different file as input:
			//TsaClientHelper.verify(f.toURI().toURL(),timestampResponse,new java.net.URL(server+"/chain.pem"));

			//so if you use a timestampingserver with a CA certificate already trusted by Java:
			de.elbosso.util.security.TsaClientHelper.verify(f.toURI().toURL(),timestampResponse);
			//to check the timestamp and make it fail - just use a different file as input:
			//TsaClientHelper.verify(fi.toURI().toURL(),timestampResponse);

			//of course, the method above may not be what you want because it tries to fetch all CRLs of all CAs
			//in the JREs truststore - better because aof it being faster is to give the trusted root for the certificate
			//used to do the signing shown here for the example entrust:
			//TsaClientHelper.verify(f.toURI().toURL(),timestampResponse,new java.net.URL("https://web.entrust.com/root-certificates/entrust_2048_ca.cer"));
			//to check the timestamp and make it fail - just use a different file as input:
			//TsaClientHelper.verify(fi.toURI().toURL(),timestampResponse,new java.net.URL("https://web.entrust.com/root-certificates/entrust_2048_ca.cer"));

		}
		catch(Throwable t)
		{
			System.out.println("##error##");
			t.printStackTrace();
		}
	}
}