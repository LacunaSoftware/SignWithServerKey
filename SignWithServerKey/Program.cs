using Lacuna.RestPki.Api.PadesSignature;
using Lacuna.RestPki.Api;
using System;
using Lacuna.RestPki.Client;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignWithServerKey{
	internal class Program{
		public const string RestPKIAccessToken = "";
		public const string FileToSignName = "Sample.pdf";
		public const string FileSignedName = "SampleSigner.pdf";
		public const string SignatureImage = "PdfStamp.png";
		public const string CertificatePath = "Wayne Enterprises, Inc.pfx";
		public const string CertificatePassword = "1234";

		public const string SignerUrl = "";
		public const string SignerApiKey = "";
		public const string SignerFolder = "";

		public const string SignerEmail = "";

		

		static void Main(string[] args) {
			AssinaturaRestPKI();
		}

		static void AssinaturaRestPKI() {
			var certificate = new X509Certificate2(CertificatePath, CertificatePassword);
			var restPkiClient = new RestPkiClient("https://pki.rest/", RestPKIAccessToken);
			var signatureStarter = new PadesSignatureStarter(restPkiClient) {
				MeasurementUnits = PadesMeasurementUnits.Centimeters,
				SignaturePolicyId = StandardPadesSignaturePolicies.Basic,
#if DEBUG
				SecurityContextId = StandardSecurityContexts.LacunaTest,
#else
			SecurityContextId=Lacuna.RestPki.Api.StandardSecurityContexts.PkiBrazil
#endif
				VisualRepresentation = GetVisualRepresentationForRestPki(restPkiClient)
			};
			signatureStarter.SetSignerCertificate(certificate.RawData);
			signatureStarter.SetPdfToSign(FileToSignName);
			var start = signatureStarter.Start();

			var key = certificate.GetRSAPrivateKey();
			var signature = key.SignHash(start.ToSignHash, HashAlgorithmNameFromOid(start.DigestAlgorithmOid), RSASignaturePadding.Pkcs1);
			// Finish
			var signatureFinisher = new PadesSignatureFinisher2(restPkiClient) {
				Token = start.Token,
				Signature = signature,
			};
			var result = signatureFinisher.Finish();
			var signedPdf = result.GetContent();
			File.WriteAllBytes(FileSignedName,signedPdf);
			System.Console.WriteLine($"{FileToSignName} signed by {certificate.FriendlyName}");
			System.Console.ReadKey();
		}

		public static PadesVisualRepresentation GetVisualRepresentationForRestPki(RestPkiClient restPkiClient) {

			// Create a visual representation.
			var visualRepresentation = new PadesVisualRepresentation() {
				// For a full list of the supported tags, see:
				// https://github.com/LacunaSoftware/RestPkiSamples/blob/master/PadesTags.md
				Text = new PadesVisualText("Signed by {{name}} ({{national_id}})") {
					FontSize = 13.0,
					IncludeSigningTime = true,
					HorizontalAlign = PadesTextHorizontalAlign.Left,
					Container = new PadesVisualRectangle() {
						Left = 0.2,
						Top = 0.2,
						Right = 0.2,
						Bottom = 0.2
					}
				},
				Image = new PadesVisualImage(File.ReadAllBytes(SignatureImage), "image/png") {
					HorizontalAlign = PadesHorizontalAlign.Right,
					VerticalAlign = PadesVerticalAlign.Center
				},
			};
			var visualPositioning = PadesVisualPositioning.GetFootnote(restPkiClient);
			visualPositioning.Container.Height = 4.94;
			visualPositioning.SignatureRectangleSize.Width = 8.0;
			visualPositioning.SignatureRectangleSize.Height = 4.94;
			visualRepresentation.Position = visualPositioning;
			return visualRepresentation;
		}

		static HashAlgorithmName HashAlgorithmNameFromOid(string oid) {
			switch (oid) {
				case "1.3.14.3.2.26":
					return HashAlgorithmName.SHA1;
				case "2.16.840.1.101.3.4.2.1":
					return HashAlgorithmName.SHA256;
				case "2.16.840.1.101.3.4.2.3":
					return HashAlgorithmName.SHA512;
				default:
					throw new NotSupportedException($"Not supported digest algorithm: {oid}");
			}
		}
	}
}
