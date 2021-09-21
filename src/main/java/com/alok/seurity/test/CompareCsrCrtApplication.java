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

		String strThing2Csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
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

		String strThing2CsrAgainSameKeys = "-----BEGIN CERTIFICATE REQUEST-----\n" +
				"MIICVzCCAT8CAQAwEjEQMA4GA1UEAwwHdGhpbmctMjCCASIwDQYJKoZIhvcNAQEB\n" +
				"BQADggEPADCCAQoCggEBAL22N3v5hi+TIia5w26v1w/VCPPY5n27KQO72cS2wIIE\n" +
				"r056/QQdiBgThO11bXaUX9TPneN1ye4Krjty+8y+D3Ao3s5z3OZI5yc6pWSlY44n\n" +
				"hNAcDQipX51iMcku34mV8nSrfB1fM5ZMfgKQF/CKgaPUUQRw6cnJJ1t1eAk/zy2o\n" +
				"8bXBHyRndcKLZXimgGcKa0koShpDez7V2YlkYcE0uo0atuXarhE8aXgVH3qDr7Wp\n" +
				"qf8E2TqKBrY/ENSwkQhX5x/wwi2kwgHazHt9AB+tvVATb6Uc5iMXAayrYMSemg08\n" +
				"LQvDL5/Ev6gbEWpUotyd4n2H47ynGIk8gbt78sdBExcCAwEAAaAAMA0GCSqGSIb3\n" +
				"DQEBCwUAA4IBAQBQ1VrxfAYiBHDvvd7GZrmreRxpjNmKXC3hhJ8f2TRQe7Wn4iY0\n" +
				"6ah8jadyBlznxn5dRIDvvrezi4GJRWlr2oXhzT+ZwapyfSq9F21SyTxml/FUyPGr\n" +
				"x2SI8TeORlVOzuT2Y2zelU8rdL3ewk+HgqrvSsMVxORbeTsVGmOLLkggPyLy9zw9\n" +
				"c7emwe30M5GAAt261R7Znhuj7ZVMbbCR27Kq89MP4Tia+9YOL8ZGRvEzw0KgmNFI\n" +
				"kGbZMjyz8F1Jt/nhD7B/H8/cLKBLWa585wvsUIgLNHCQPx7EPsZ3FC82DME/WFFY\n" +
				"va1xu3vXJi+LoxIdbeYAOyMzUN4M840TAsc3\n" +
				"-----END CERTIFICATE REQUEST-----";

		String strThing2Crt = "-----BEGIN CERTIFICATE-----\n" +
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
				"MIIE1TCCAr2gAwIBAgIJALKDZ6nGwVsTMA0GCSqGSIb3DQEBBQUAMCExCzAJBgNV\n" +
				"BAYTAklOMRIwEAYDVQQKDAlBbG9rIFNlbGYwHhcNMjAxMjA5MTIzMjM0WhcNMzAx\n" +
				"MjA3MTIzMjM0WjAhMQswCQYDVQQGEwJJTjESMBAGA1UECgwJQWxvayBTZWxmMIIC\n" +
				"IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvoJktEPi6VCaajZumXJxCFqV\n" +
				"I0thOY+tcnrOa+YjZsLc7mu1q9YcMN1SLhQyxkYVO6wSKEI6B51bosmJfDCTnc55\n" +
				"Gvsb10S3YkCmCQ2gAoo1wpeBrFNOFuxUf4ACdBjIO1DhW7f0oMY+geKVF9QrT1Pm\n" +
				"+TmsR1ALu4wWklqHcNbKAwt68JxlVF/qqfX08uLQ2qJ4UaftnpRWKDNLRgbPVcg+\n" +
				"Y7YH9DeqkDh1U6ncsRA+x60ARFEtuVQDU0vElhWzfGOujCK2xXhtE1Mv7LOWp4cH\n" +
				"3YHpRpB+Y1EUrUhoFinA5dsFseuOSz4vAiqR5MY2F5hcA26aRcLwZrc5kRJ8tGG3\n" +
				"7ixat4yKio5F08Ke7dk1qDnpoz0xohuYIU4mfzLmLlIY+pqeIW79Ch/U4no/GX1h\n" +
				"PFdbTE7hVL0s2R04g+S7xTK31zn5nb53apYxfcBox48b4izD2wMYyAfCETYKz4BU\n" +
				"ajMcf645uVANo7xAC5jrev+ZwDS7OsYzIyrrb2fH3Bi8fsuXXFAT72gAYS4HPqzU\n" +
				"1Hs35sN68Kh5MuocVXY41Po93BSSjoWwEcyEomXSnuPhI3pQaNUt6BaLoO6Hglbv\n" +
				"W/ZABC8dl+GS4VqDlIFKfj0hnNExZZeElddCUnCfpC5HjreywCFf9kodQvagVm+5\n" +
				"YqfOxtelk2VLh1/xWekCAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\n" +
				"AQUFAAOCAgEAGVr5qG8Cae0B3coYdZrKsb7XT44kNeGCmJdUJoWXsiBRxwMLRfHy\n" +
				"1S1JCLnbn7VWMCiiLP+PYmrbBWWrLrImPUaTAZnxA4PkLPaTvGORUR9toqNU/VeV\n" +
				"WWNjV72bxVVDwgOp3e2pADkkDsD+Y6I9kGgxBVM7AguM75BwzmQR7cIw1voCsnrj\n" +
				"191ehUJR7YU9dL7lAZDB6pOvfSr2M9AsrfD+Vo5akPT6RjvWOxbgK789CiyV0/El\n" +
				"2kZgiAHww6a885ANDmKGU/BFmnKb5QXDFs+/0jBpnqiB27nVCekVDD6q08XQ65x3\n" +
				"Swun1BS2Xg3k1XGVhF1Iai2gxes93UlEA0/QSgMTDLDx6uI0KLwhUu+i6WnKXwDi\n" +
				"rIcUYkfagY8omGa4hOXSswN7uRvdAYCZPT3IL2p5niVFnLsl7HnkrUiXJG01PDMt\n" +
				"MX59hKP8U6P+U0BoFuprx63UvKJhRXMV6TOB9BWQdvkWNA8vejTzoInRh0HOtoxn\n" +
				"A1AjTDZ850vz16ETV06/2WM/ASu7rldBwOrX8By733HIgsaX5kRfajQOGtrHMpKu\n" +
				"b6VpB5x0dBHRWjuQI3awxQV82AsMi+IPYaxeOq0XvYSzfiLL7tDdyICl4ThJheH+\n" +
				"woJkohk0AvTJmZ+z5fipWNvZhs2dWAKknzfJctwpU2wbztnhe5BYR84=\n" +
				"-----END CERTIFICATE-----";

		String strThing1Csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
				"MIIEqjCCApICAQAwZTELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUtlcm5hdGFrYTET\n" +
				"MBEGA1UEBwwKQmVuYWdsdXJ1cjENMAsGA1UECgwESG9tZTENMAsGA1UECwwEU2Vs\n" +
				"ZjEPMA0GA1UEAwwGdGhpbmcxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\n" +
				"AgEA0b0r8YS+JpN6S7DYn3qK/+tAFzwhDosANoIWTKNxDWRlEOnnW6tHMejBUHPl\n" +
				"yNSKyAjVVScLrA4UCVHodp6/7enbD6r53lyY+0QIiH+cJILokS4AfsqNltrcyqHW\n" +
				"AfISqItl9tQLUiwDeNMJJoOk9RrOmFpiDqUYDXF0eLWWDXnBe+GOm/SNfpeFKRJ/\n" +
				"DOW1xSPytQxACQceezftCqJhWJtsc+/r5IvkLGFLc9e5UI5K+XXwJ6ubdEySB/C/\n" +
				"Mxz8HTZPzkNS2kUCX0wc1HSFBBKO0z0wfCtW32ObdQeMRlYKGyfhBS2GNjYyHpAa\n" +
				"PFKb2pla0THzCqcIHljwMAynFAuyNk4EBVkM+2IEITBVzxzpUrOOU8H+bwXb0VPZ\n" +
				"N1xKlgtmHWi6yJPqTkr98qn21qLytpa13sC8OgPdYf+N9FocVLlRXdCbOjzrzz7C\n" +
				"DMP3twCTKKav5AdSdh/ofnUv0/rdUMow85SUXNPVCT7sOiiTh6PZuF4WFuZd6MuY\n" +
				"7QVbeeO7EL9yl0fFUvkVnG+XjujLTmzzjjuILUDBUhFhLLQqpyTocltRJs54ZlAO\n" +
				"rsKzOrySYIoUKSSPNw+uGODrZGJKXLTcthpw+6wt2pSHoPd8SBtFiXgTpd73cIZj\n" +
				"szdFHPpgIIJpbkUzv+i0UgxchtbCLTMKFsji3RUJN1F1IekCAwEAAaAAMA0GCSqG\n" +
				"SIb3DQEBCwUAA4ICAQA3KV3awwtlNy4jRGxXDt9+QlIL1ioWqeAUIwn1mJ2ABCuX\n" +
				"jFDfLXF2CtDrQMFKqwAVrGPvaRj6+kX6WxMy9Wg90tgDEDtiv3GxZ1+mTNZdGczr\n" +
				"+RXfKheKveQLlXQvxcVzPrfarIaOlgZKzNbCTJubjdZ2fTD3fB0B/EXFSZnyxvhb\n" +
				"7wja5Gz1uSy21v3uBdGsxHAdzj/dsrThW0Ov45QeuAaQ3huvsUyse1vpi3VdXEgA\n" +
				"x0OAPrACpMZWwIYx3IT67SiG2T28EIEW5FwXjCw/Jq0D+XOhLN/8gOrrQJalbWz7\n" +
				"rE3UepZsvry7ZPp+54/XLrX/d2OjiFHjdiDggfYmM9IWyOQNJt6pgY/v64yFHjgM\n" +
				"nTRcZcT7aJEp029/4CWswIpbRgaXgKl8K8a1KprmuDPLhLVB5OOpj9+UKtZ/IDAr\n" +
				"aQdQTsd1hmrM4DzEiig6pyQrNn5ZjcEm4b5WvgbBqScQiM2Y+xtCSoaKdDdT77dM\n" +
				"wL/xhQBRpVDU2e/d6P9DonPYb/eZH6+pbM2HtC1669qJdxLl74JOJCDahC4iBBTF\n" +
				"PBOdYkAQf/YLpBqWoD4NEXpIW/U6JCgo8lbHOwIEiJwpvJJN/Mg5kq0Ya6kIt4Zx\n" +
				"v76JnkS8DfLtPOVdH8kV2bqblufO02Q2iFYI8gv+o3cnd7HFPzBWCITBPbXPew==\n" +
				"-----END CERTIFICATE REQUEST-----";

		String strThing1Crt = "-----BEGIN CERTIFICATE-----\n" +
				"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\n" +
				"-----END CERTIFICATE-----";


		System.out.format("\t%-50s: %s\n", "Thing 2 Crt FInger Print", getPublicKeyModulusMd5(getPublicKeyFromCrt(strThing2Crt)));
		System.out.format("\t%-50s: %s\n", "Thing 2 Csr FInger Print", getPublicKeyModulusMd5(getPublicKeyFromCsr(strThing2Csr)));
		System.out.format("\t%-50s: %s\n", "Thing 2 Csr FInger Print once again same keys", getPublicKeyModulusMd5(getPublicKeyFromCsr(strThing2CsrAgainSameKeys)));
		System.out.format("\t%-50s: %s\n", "Other Crt FInger Print", getPublicKeyModulusMd5(getPublicKeyFromCrt(strOtherCrt)));
		System.out.format("\t%-50s: %s\n", "Thing 1 Crt FInger Print", getPublicKeyModulusMd5(getPublicKeyFromCrt(strThing1Crt)));
		System.out.format("\t%-50s: %s\n", "Thing 1 Csr FInger Print", getPublicKeyModulusMd5(getPublicKeyFromCsr(strThing1Csr)));



		System.out.println("I am done!");
	}

	public static String getPublicKeyFromCsr(String strCsr) throws IOException {

		PEMParser pemParser = new PEMParser(new StringReader(strCsr));
		Object object = pemParser.readObject();
		PKCS10CertificationRequest csr = null;
		if (object instanceof PKCS10CertificationRequest) {
			PKCS10CertificationRequest holder = (PKCS10CertificationRequest) object;
			StringWriter output = new StringWriter();
			PemWriter pemWriter = new PemWriter(output);
			PemObject pkPemObject = new PemObject("PUBLIC KEY",
					holder.getSubjectPublicKeyInfo().getEncoded());

			pemWriter.writeObject(pkPemObject);
			pemWriter.close();

			return new String(output.getBuffer());
		} else {
			System.out.println("Object is not type of PKCS10CertificationRequest");
			return null;
		}
	}

	public static String getPublicKeyFromCrt(String strCert) throws IOException {

		PEMParser pemParser = new PEMParser(new StringReader(strCert));
		Object object = pemParser.readObject();
		X509Certificate cert = null;
		if (object instanceof X509CertificateHolder) {
			X509CertificateHolder holder = (X509CertificateHolder) object;
			StringWriter output = new StringWriter();
			PemWriter pemWriter = new PemWriter(output);

			PemObject pkPemObject = new PemObject("PUBLIC KEY",
					holder.getSubjectPublicKeyInfo().getEncoded());


			pemWriter.writeObject(pkPemObject);
			pemWriter.close();

			return new String(output.getBuffer());

		} else {
			System.out.println("Object is not type of X509CertificateHolder");
			return null;
		}
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
