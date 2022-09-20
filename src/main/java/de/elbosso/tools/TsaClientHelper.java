package de.elbosso.tools;

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

import de.elbosso.util.io.Utilities;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class TsaClientHelper
{
	private final static org.slf4j.Logger CLASS_LOGGER = org.slf4j.LoggerFactory.getLogger(TsaClientHelper.class);

	private TsaClientHelper()
	{
		super();
	}
	public static byte[] getResponse(byte[] timestampQuery,java.lang.String server) throws java.io.IOException
	{
		java.net.HttpURLConnection con;
		java.net.URL url = new java.net.URL(server);
		con = (java.net.HttpURLConnection) url.openConnection();
		con.setDoOutput(true);
		con.setDoInput(true);
		con.setRequestProperty("Content-type", "application/timestamp-query");
		con.setRequestProperty("Content-length", String.valueOf(timestampQuery.length));
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.info("TSA server was successfully contacted");

		// send request
		java.io.OutputStream out;
		out = con.getOutputStream();
		java.io.ByteArrayInputStream bais=new java.io.ByteArrayInputStream(timestampQuery);
		de.elbosso.util.io.Utilities.copyBetweenStreams(bais,out,false);
		bais.close();
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("TS request sent");

		// receive response
		java.io.InputStream in;
		// verify connection status
		if ((con.getResponseCode()<200 )||(con.getResponseCode()>299)) {
			throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
		} else {
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("Response Code: "+ con.getResponseCode());
		}
		// accept the answer
		in = con.getInputStream();
		java.io.ByteArrayOutputStream baos=new java.io.ByteArrayOutputStream();
		de.elbosso.util.io.Utilities.copyBetweenStreams(in,baos,false);
		baos.close();
		return baos.toByteArray();
	}
	public static byte[] makeQuery(java.net.URL content, boolean includeCertificate, java.lang.String policyOID) throws IOException, NoSuchAlgorithmException
	{
		org.bouncycastle.tsp.TimeStampRequestGenerator generator = new org.bouncycastle.tsp.TimeStampRequestGenerator();
		if(policyOID!=null)
			generator.setReqPolicy(new ASN1ObjectIdentifier(policyOID));
		generator.setCertReq(includeCertificate);
		java.io.InputStream is = content.openStream();
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		Utilities.copyBetweenStreams(is, baos, true);
		MessageDigest digest = MessageDigest.getInstance(TSPAlgorithms.SHA512.toString());
		byte[] in = baos.toByteArray();
		byte[] out = digest.digest(in);
		SecureRandom secureRand=null;
		try
		{
			secureRand = SecureRandom.getInstance("NativePRNG");
		}
		catch(java.security.NoSuchAlgorithmException nsaexp)
		{
			CLASS_LOGGER.warn(nsaexp.getMessage(),nsaexp);
			secureRand=SecureRandom.getInstanceStrong();
		}
		org.bouncycastle.tsp.TimeStampRequest request = generator.generate(TSPAlgorithms.SHA512, out, new BigInteger(64,secureRand));
		byte[] timestamp = request.getEncoded();
		return timestamp;
	}
	public static void verify(java.net.URL content, java.net.URL tsr) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		verify(content,tsr,null);
	}
	public static void verify(java.net.URL content, java.net.URL tsr,java.net.URL pemChainUrl) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		java.io.InputStream inputStream = tsr.openStream();
		org.bouncycastle.tsp.TimeStampResponse timeStampResponse = new org.bouncycastle.tsp.TimeStampResponse(inputStream);
		inputStream.close();
		verify(content,timeStampResponse,pemChainUrl);
	}
	public static void verify(java.net.URL content, byte[] tsr) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		verify(content,tsr,null);
	}
	public static void verify(java.net.URL content, byte[] tsr,java.net.URL pemChainUrl) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		java.io.InputStream inputStream = new java.io.ByteArrayInputStream(tsr);
		org.bouncycastle.tsp.TimeStampResponse timeStampResponse = new org.bouncycastle.tsp.TimeStampResponse(inputStream);
		inputStream.close();
		verify(content,timeStampResponse,pemChainUrl);
	}
	public static void verify(java.net.URL content, TimeStampResponse tsr) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		verify(content,tsr,null);
	}
	public static void verify(java.net.URL content, TimeStampResponse tsr, java.net.URL pemChainUrl) throws java.io.IOException, org.bouncycastle.tsp.TSPException, java.security.cert.CertificateException, java.security.NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException, java.security.KeyStoreException, org.bouncycastle.operator.OperatorCreationException
	{
		if ((0 != tsr.getStatus())&&(1 != tsr.getStatus()))
		{
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("status: " + tsr.getStatus());
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("status string: " + tsr.getStatusString());
			org.bouncycastle.asn1.cmp.PKIFailureInfo failInfo = tsr.getFailInfo();
			if (null != failInfo)
			{
				if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("fail info int value: " + failInfo.intValue());
				if (org.bouncycastle.asn1.cmp.PKIFailureInfo.unacceptedPolicy == failInfo.intValue())
				{
					if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("unaccepted policy");
				}
			}
			throw new org.bouncycastle.tsp.TSPException("timestamp response status != 0: "
					+ tsr.getStatus()+" ("+tsr.getStatusString()+")");
		}
		// TSP response parsing and validation
		org.bouncycastle.tsp.TimeStampToken timeStampToken = tsr.getTimeStampToken();
		org.bouncycastle.tsp.TimeStampRequestGenerator generator = new org.bouncycastle.tsp.TimeStampRequestGenerator();
		generator.setReqPolicy(timeStampToken.getTimeStampInfo().getPolicy());
		java.io.InputStream is = content.openStream();
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		Utilities.copyBetweenStreams(is, baos, true);
		MessageDigest digest = MessageDigest.getInstance(timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().toString());
		byte[] in = baos.toByteArray();
		byte[] out = digest.digest(in);
		org.bouncycastle.tsp.TimeStampRequest tsq = generator.generate(timeStampToken.getTimeStampInfo().getMessageImprintAlgOID(), out, timeStampToken.getTimeStampInfo().getNonce());

		verify(tsq,tsr,pemChainUrl);
	}

	public static void verify(TimeStampRequest tsq, TimeStampResponse tsr, java.net.URL pemChainUrl) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, TSPException, OperatorCreationException
	{
		if ((0 != tsr.getStatus())&&(1 != tsr.getStatus()))
		{
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("status: " + tsr.getStatus());
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("status string: " + tsr.getStatusString());
			org.bouncycastle.asn1.cmp.PKIFailureInfo failInfo = tsr.getFailInfo();
			if (null != failInfo)
			{
				if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("fail info int value: " + failInfo.intValue());
				if (org.bouncycastle.asn1.cmp.PKIFailureInfo.unacceptedPolicy == failInfo.intValue())
				{
					if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("unaccepted policy");
				}
			}
			throw new org.bouncycastle.tsp.TSPException("timestamp response status != 0: "
					+ tsr.getStatus()+" ("+tsr.getStatusString()+")");
		}
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("policy "+tsr.getTimeStampToken().getTimeStampInfo().getPolicy());
		org.bouncycastle.tsp.TimeStampToken timeStampToken = tsr.getTimeStampToken();
		org.bouncycastle.cms.SignerId signerId = timeStampToken.getSID();
		java.math.BigInteger signerCertSerialNumber = signerId.getSerialNumber();
		X500Name signerCertIssuer = signerId.getIssuer();
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("signer cert serial number: " + signerCertSerialNumber);
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("signer cert issuer: " + signerCertIssuer);

		// TSP signer certificates retrieval
		org.bouncycastle.util.Store certStore = timeStampToken.getCertificates();
		java.util.Collection<org.bouncycastle.cert.X509CertificateHolder> certificates = certStore.getMatches(null);
		java.security.cert.X509Certificate signerCert = null;
		java.util.Map<String, java.security.cert.X509Certificate> certificateMap = new java.util.HashMap<String, java.security.cert.X509Certificate>();
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X509");
		java.util.List<X509CRL> crls=new java.util.LinkedList();
		for (org.bouncycastle.cert.X509CertificateHolder ch : certificates)
		{
			java.security.cert.X509Certificate x509Certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
					.getCertificate(ch);
			String ski = de.elbosso.util.Utilities.formatHexDump(de.elbosso.util.security.Utilities.getSubjectKeyId(x509Certificate));
			certificateMap.put(ski, x509Certificate);
			if (signerCertIssuer.equals(ch
					.getIssuer())
					&& signerCertSerialNumber.equals(x509Certificate
					.getSerialNumber()))
			{
				signerCert = x509Certificate;
				if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("embedded signer certificate: "
						+ x509Certificate.getSubjectX500Principal() + "; SKI="
						+ ski);
			}
			else
			{
				if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("embedded certificate: "
						+ x509Certificate.getSubjectX500Principal() + "; SKI="
						+ ski);
			}
			crls.addAll(de.elbosso.util.security.Utilities.getCRLs(x509Certificate));
		}

		// TSP signer cert path building
		if (null == signerCert)
		{
			throw new RuntimeException(
					"TSP response token has no signer certificate");
		}
		java.util.List<java.security.cert.X509Certificate> tspCertificateChain = new java.util.LinkedList<java.security.cert.X509Certificate>();
		java.security.cert.X509Certificate certificate = signerCert;
		do
		{
			if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("adding to certificate chain: "
					+ certificate.getSubjectX500Principal());
			tspCertificateChain.add(certificate);
			if (certificate.getSubjectX500Principal().equals(
					certificate.getIssuerX500Principal()))
			{
				break;
			}
			String aki = de.elbosso.util.Utilities.formatHexDump(de.elbosso.util.security.Utilities.getAuthorityKeyId(certificate));
			X500Principal issuer=certificate.getIssuerX500Principal();
			java.util.List<java.lang.String> authorityInfoURIs=de.elbosso.util.security.Utilities.getAuthorityInfoAccess(certificate);
			certificate = certificateMap.get(aki);
			if(certificate==null)
			{
				CLASS_LOGGER.debug("did not find certificate for: "+issuer+" ("
						+ aki+"} in available certificates");
				CLASS_LOGGER.debug(java.util.Objects.toString(authorityInfoURIs));
				for(java.lang.String authorityInfoURI:authorityInfoURIs)
				{
					try
					{
						java.net.URL pemUrl = new java.net.URI(authorityInfoURI).toURL();
						CLASS_LOGGER.debug("Trying to load certificate for {} from {}",issuer,pemUrl);
						java.io.InputStream is = pemUrl.openStream();
						java.io.InputStream caInput = new java.io.BufferedInputStream(is);
						java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(caInput);
						caInput.close();
						if(certs.isEmpty()==false)
						{
							certificate=(X509Certificate) certs.iterator().next();
							CLASS_LOGGER.debug("Loaded certificate for {}",certificate.getSubjectX500Principal());
							crls.addAll(de.elbosso.util.security.Utilities.getCRLs(certificate));
							CLASS_LOGGER.debug("Loaded CRL(s) for {}",certificate.getSubjectX500Principal());
						}
					}
					catch(java.net.URISyntaxException exp)
					{
						CLASS_LOGGER.warn(exp.getMessage(),exp);
					}
				}
			}
		}
		while (null != certificate);
		javax.net.ssl.TrustManagerFactory factory = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
		java.security.cert.CertPath certpath = cf.generateCertPath(tspCertificateChain);
		java.security.cert.CertPathValidator validator = java.security.cert.CertPathValidator.getInstance("PKIX");
//		java.security.KeyStore keystore = de.elbosso.util.security.Utilities.createKeystoreWithCacertsTrustedRoots();
		java.security.KeyStore keystore=pemChainUrl!=null?de.elbosso.util.security.Utilities.readChainFromPem(pemChainUrl):de.elbosso.util.security.Utilities.createKeystoreWithJDKsTrustedRoots();

		if(pemChainUrl==null)
		{
			for(java.security.cert.X509Certificate chainCert:tspCertificateChain)
				keystore.setCertificateEntry(de.elbosso.util.Utilities.formatHexDump(de.elbosso.util.security.Utilities.getSubjectKeyId(chainCert)),chainCert);
		}

		java.util.Enumeration en = keystore.aliases();
		if(pemChainUrl!=null)
		{
			while (en.hasMoreElements())
			{
				java.lang.String alias = en.nextElement().toString();
				if (CLASS_LOGGER.isDebugEnabled()) CLASS_LOGGER.debug("keystore element: "
						+ alias);
				crls.addAll(de.elbosso.util.security.Utilities.getCRLs((X509Certificate) keystore.getCertificate(alias)));
			}
		}

		// This class retrieves the most-trusted CAs from the keystore
		java.security.cert.PKIXParameters params = new java.security.cert.PKIXParameters(keystore);
		java.security.cert.CertStoreParameters revoked = new java.security.cert.CollectionCertStoreParameters(crls);
		params.addCertStore(java.security.cert.CertStore.getInstance("Collection", revoked));
		params.setRevocationEnabled(true);
		CLASS_LOGGER.debug(java.lang.Boolean.toString(params.isRevocationEnabled()));
		try
		{
			validator.validate(certpath, params);
		}
		catch (java.security.cert.CertPathValidatorException exp)
		{
			throw new java.lang.RuntimeException(exp);
		}
		// verify TSP signer signature
		org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder sigVerifBuilder = new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder();
		org.bouncycastle.cms.SignerInformationVerifier signerInfoVerif = sigVerifBuilder.setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME).build(signerCert);
		timeStampToken.validate(signerInfoVerif);

//                // verify TSP signer certificate
//                this.validator.validate(tspCertificateChain, revocationData);
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("time-stamp token time: "
				+ timeStampToken.getTimeStampInfo().getGenTime());
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("time-stamp authority: "
				+ timeStampToken.getTimeStampInfo().getTsa());
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("time-stamp message imprint algorithm OID: "
				+ timeStampToken.getTimeStampInfo().getMessageImprintAlgOID());
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("message imprint digest: "
				+ de.elbosso.util.Utilities.formatHexDump(timeStampToken.getTimeStampInfo().getMessageImprintDigest()));
		if(CLASS_LOGGER.isDebugEnabled())CLASS_LOGGER.debug("request message imprint digest: "
				+ de.elbosso.util.Utilities.formatHexDump(tsq.getMessageImprintDigest()));
		tsr.validate(tsq);
	}

}
