package com.alok.seurity.test;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@SpringBootApplication
public class CompareCsrCrtApplication {

	public static void main(String[] args) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
		SpringApplication.run(CompareCsrCrtApplication.class, args);

		String strCsr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
				"MIICizCCAXMCAQAwRjELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTES\n" +
				"MBAGA1UEBwwJQmVuYWdsdXJ1MQ8wDQYDVQQDDAZ0aGluZzIwggEiMA0GCSqGSIb3\n" +
				"DQEBAQUAA4IBDwAwggEKAoIBAQC9tjd7+YYvkyImucNur9cP1Qjz2OZ9uykDu9nE\n" +
				"tsCCBK9Oev0EHYgYE4TtdW12lF/Uz53jdcnuCq47cvvMvg9wKN7Oc9zmSOcnOqVk\n" +
				"pWOOJ4TQHA0IqV+dYjHJLt+JlfJ0q3wdXzOWTH4CkBfwioGj1FEEcOnJySdbdXgJ\n" +
				"P88tqPG1wR8kZ3XCi2V4poBnCmtJKEoaQ3s+1dmJZGHBNLqNGrbl2q4RPGl4FR96\n" +
				"g6+1qan/BNk6iga2PxDUsJEIV+cf8MItpMIB2sx7fQAfrb1QE2+lHOYjFwGsq2DE\n" +
				"npoNPC0Lwy+fxL+oGxFqVKLcneJ9h+O8pxiJPIG7e/LHQRMXAgMBAAGgADANBgkq\n" +
				"hkiG9w0BAQsFAAOCAQEATWl1Jz695MezlIss8mvhW1vnC2szXtgC0fRJdvk0qEkS\n" +
				"BeqrtRMxiqkxERVvmVmRZL/yhqAZs6pY3EBH+iEz+psjFgDp1BEoy6BLugsYxdQd\n" +
				"wx3txG7u4jeopqTNUjha3mbcNY3Opu4lUujL3pqUdM/RMCDkS4adfZ+FWkIuXiBp\n" +
				"cOa3tLrmg2ABBav8vk2Py8Sp7DLqoJMu22tcwPRgXN4RcPvGP6ew/01Oq3NprZJy\n" +
				"hB4vvjokcFX1S8y7PTpa+jOvJKNTL32xZKJjF40QTvVTw1EQ2s6a6jzcKRoECMjH\n" +
				"23NsVMZbZrKSKEs+pBBZNWz4haG/tBreKNfmmf/GEg==\n" +
				"-----END CERTIFICATE REQUEST-----";

		String strCrt = "-----BEGIN CERTIFICATE-----\n" +
				"MIID4zCCAcsCCQD8/DuY78QlDzANBgkqhkiG9w0BAQsFADAhMQswCQYDVQQGEwJJ\n" +
				"TjESMBAGA1UECgwJQWxvayBTZWxmMB4XDTIwMTIwOTE0MjA1NVoXDTIyMDQyMzE0\n" +
				"MjA1NVowRjELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTESMBAGA1UE\n" +
				"BwwJQmVuYWdsdXJ1MQ8wDQYDVQQDDAZ0aGluZzIwggEiMA0GCSqGSIb3DQEBAQUA\n" +
				"A4IBDwAwggEKAoIBAQC9tjd7+YYvkyImucNur9cP1Qjz2OZ9uykDu9nEtsCCBK9O\n" +
				"ev0EHYgYE4TtdW12lF/Uz53jdcnuCq47cvvMvg9wKN7Oc9zmSOcnOqVkpWOOJ4TQ\n" +
				"HA0IqV+dYjHJLt+JlfJ0q3wdXzOWTH4CkBfwioGj1FEEcOnJySdbdXgJP88tqPG1\n" +
				"wR8kZ3XCi2V4poBnCmtJKEoaQ3s+1dmJZGHBNLqNGrbl2q4RPGl4FR96g6+1qan/\n" +
				"BNk6iga2PxDUsJEIV+cf8MItpMIB2sx7fQAfrb1QE2+lHOYjFwGsq2DEnpoNPC0L\n" +
				"wy+fxL+oGxFqVKLcneJ9h+O8pxiJPIG7e/LHQRMXAgMBAAEwDQYJKoZIhvcNAQEL\n" +
				"BQADggIBABVC/3gPGnmIMlhzKepeSxlZkCa54LPPvcVQViO+sdG9c/a9pySzClfH\n" +
				"pJ7O+TVI2PhD/s65cMsHpcgkOeo2HPS+tVLVmyeSHPn5ty+/2pkuFGqL+R7qBWYZ\n" +
				"ggzk54iFAIfc0OWekhtvn21QwxlxmxsN168GcA8aJTccIR2U5w1uyPxtETSXVOA3\n" +
				"ejKrCCZV7oo0MeyGyEzVTforMW0YVENDPOlydzaZAUrBny6xT6bIKk1gUrmg3V9M\n" +
				"dLHh9F+QwdyXB6Ef942yqnTluFO5fFASgE4/TkdRWgiVdiYKl9E8sk4Bp3phg5jk\n" +
				"sEst0OuhTmlEBRTVmHosiyPR0nD9OWGj32cqRlgig1W6R//sBnk0os9oW5IEp42D\n" +
				"JWQd/exayCY6OD9U/J1QerYaBT9ZV5Z7kgvsWswWTtbVY43JZd0OV0dLLvMhsdKb\n" +
				"+HDl/jKOGi2v2kNcyUW9+/GVd77o40j4/1t8T4vXN12pGI5LyFoScL7S5AqJswsk\n" +
				"7AQ2s9Njja2XY8GFXHwMV230lORi6UtHeENqtlysmSvjjfM1e9cFOdVE5p7i6HtG\n" +
				"siMiQg3RRwMDbjQjExftI1UTxDHMHFuDzF02yii3ayqjau+eLbq9nfjkEmadQ5wM\n" +
				"4p/XuNMJEjkGUKsWxtFO0OKu7a1niuRelZh44k8DJHygvYGxoy5P\n" +
				"-----END CERTIFICATE-----";

		String strOtherCrt = "-----BEGIN CERTIFICATE-----\n" +
				"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\n" +
				"-----END CERTIFICATE-----";


		//Security.addProvider(new BouncyCastleProvider());

		PEMParser pemParser = new PEMParser(new StringReader(strOtherCrt));
		Object object = pemParser.readObject();
		X509Certificate cert = null;
		if (object instanceof X509CertificateHolder) {
			X509CertificateHolder holder = (X509CertificateHolder) object;
			String fingerPrint = getPublicKeyModulusMd5(getPublicKey(holder.toASN1Structure()));
			System.out.println("Crt FInger Print: " + fingerPrint);
		} else {
			System.out.println("Object is not type of X509CertificateHolder");
		}

		pemParser = new PEMParser(new StringReader(strCsr));
		object = pemParser.readObject();
		PKCS10CertificationRequest csr = null;
		if (object instanceof PKCS10CertificationRequest) {
			PKCS10CertificationRequest holder = (PKCS10CertificationRequest) object;
			String fingerPrint = getPublicKeyModulusMd5(getPublicKey(holder));
			System.out.println("Csr FInger Print: " + fingerPrint);
		} else {
			System.out.println("Object is not type of PKCS10CertificationRequest");
		}

		System.out.println("I am done!");
	}

	public static String getPublicKey(PKCS10CertificationRequest csr) throws IOException {

		StringWriter output = new StringWriter();
		PemWriter pemWriter = new PemWriter(output);

		PemObject pkPemObject = new PemObject("PUBLIC KEY",
				csr.getSubjectPublicKeyInfo().getEncoded());

		pemWriter.writeObject(pkPemObject);
		pemWriter.close();

		return new String(output.getBuffer());
	}

	public static String getPublicKey(org.bouncycastle.asn1.x509.Certificate cert) throws IOException {

		StringWriter output = new StringWriter();
		PemWriter pemWriter = new PemWriter(output);

		PemObject pkPemObject = new PemObject("PUBLIC KEY",
				cert.getSubjectPublicKeyInfo().getEncoded());


		pemWriter.writeObject(pkPemObject);
		pemWriter.close();

		return new String(output.getBuffer());
	}

	public static String getPublicKeyModulusMd5(String pubKeyPEM) throws InvalidKeySpecException, NoSuchAlgorithmException {
		pubKeyPEM = pubKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "");

		byte[] encodedPublicKey = Base64.getMimeDecoder().decode(pubKeyPEM);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKey publicKey = (RSAPublicKey)kf.generatePublic(spec);

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Could not get fingerprint", e);
		}

		byte[] digest = messageDigest.digest(publicKey.getModulus().toByteArray());
		final StringBuilder toRet = new StringBuilder();
		for (int i = 0; i < digest.length; i++) {
			if (i != 0) toRet.append(":");
			int b = digest[i] & 0xff;
			String hex = Integer.toHexString(b);
			if (hex.length() == 1) toRet.append("0");
			toRet.append(hex);
		}
        return toRet.toString();
	}
}
