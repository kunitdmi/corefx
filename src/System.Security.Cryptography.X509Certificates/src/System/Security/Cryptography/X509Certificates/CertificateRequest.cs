// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents an abstraction over the PKCS#10 CertificationRequestInfo and the X.509 TbsCertificate,
    /// allowing callers to create self-signed or chain-signed X.509 Public-Key Certificates, as well as
    /// create a certificate signing request blob to send to a Certificate Authority (CA).
    /// </summary>
    public sealed class CertificateRequest
    {
        private readonly AsymmetricAlgorithm _key;
        private readonly X509SignatureGenerator _generator;
        private readonly RSASignaturePadding _rsaPadding;

        /// <summary>
        /// The X.500 Distinguished Name to use as the Subject in a created certificate or certificate request.
        /// </summary>
        public X500DistinguishedName SubjectName { get; }

        /// <summary>
        /// The X.509 Certificate Extensions to include in the certificate or certificate request.
        /// </summary>
        public Collection<X509Extension> CertificateExtensions { get; } = new Collection<X509Extension>();

        /// <summary>
        /// A <see cref="PublicKey" /> representation of the public key for the certificate or certificate request.
        /// </summary>
        public PublicKey PublicKey { get; }

        /// <summary>
        /// The hash algorithm to use when signing the certificate or certificate request.
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, ECDSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The string representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An ECDSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <seealso cref="X500DistinguishedName(string)"/>
        public CertificateRequest(string subjectName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            SubjectName = new X500DistinguishedName(subjectName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, ECDSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An ECDSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        public CertificateRequest(X500DistinguishedName subjectName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            SubjectName = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, RSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The string representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An RSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <param name="padding">
        ///   The RSA signature padding to apply if self-signing or being signed with an <see cref="X509Certificate2" />.
        /// </param>
        /// <seealso cref="X500DistinguishedName(string)"/>
        public CertificateRequest(string subjectName, RSA key, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            SubjectName = new X500DistinguishedName(subjectName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, padding);
            _rsaPadding = padding;
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, RSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   An RSA key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <param name="padding">
        ///   The RSA signature padding to apply if self-signing or being signed with an <see cref="X509Certificate2" />.
        /// </param>
        public CertificateRequest(
            X500DistinguishedName subjectName,
            RSA key,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            SubjectName = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, padding);
            _rsaPadding = padding;
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        // begin: gost

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, ECDSA key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The string representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   A Gost key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        /// <seealso cref="X500DistinguishedName(string)"/>
        public CertificateRequest(string subjectName, Gost3410 key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            SubjectName = new X500DistinguishedName(subjectName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForGost(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, GOST3410 key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="key">
        ///   n GOST3410 key whose public key material will be included in the certificate or certificate request.
        ///   This key will be used as a private key if <see cref="CreateSelfSigned" /> is called.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        public CertificateRequest(X500DistinguishedName subjectName, Gost3410 key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            SubjectName = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForGost(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        // end: gost

        /// <summary>
        /// Create a CertificateRequest for the specified subject name, encoded public key, and hash algorithm.
        /// </summary>
        /// <param name="subjectName">
        ///   The parsed representation of the subject name for the certificate or certificate request.
        /// </param>
        /// <param name="publicKey">
        ///   The encoded representation of the public key to include in the certificate or certificate request.
        /// </param>
        /// <param name="hashAlgorithm">
        ///   The hash algorithm to use when signing the certificate or certificate request.
        /// </param>
        public CertificateRequest(X500DistinguishedName subjectName, PublicKey publicKey, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

            SubjectName = subjectName;
            PublicKey = publicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest object representing the current state
        /// of this object.
        /// </summary>
        /// <returns>A DER-encoded certificate signing request.</returns>
        /// <remarks>
        ///   When submitting a certificate signing request via a web browser, or other graphical or textual
        ///   interface, the input is frequently expected to be in the PEM (Privacy Enhanced Mail) format,
        ///   instead of the DER binary format. To convert the return value to PEM format, make a string
        ///   consisting of <c>-----BEGIN CERTIFICATE REQUEST-----</c>, a newline, the Base-64-encoded
        ///   representation of the request (by convention, linewrapped at 64 characters), a newline,
        ///   and <c>-----END CERTIFICATE REQUEST-----</c>.
        /// 
        ///   <code><![CDATA[
        ///     public static string PemEncodeSigningRequest(CertificateRequest request, PkcsSignatureGenerator generator)
        ///     {
        ///         byte[] pkcs10 = request.CreateSigningRequest(generator);
        ///         StringBuilder builder = new StringBuilder();
        ///     
        ///         builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        ///     
        ///         string base64 = Convert.ToBase64String(pkcs10);
        ///     
        ///         int offset = 0;
        ///         const int LineLength = 64;
        ///     
        ///         while (offset < base64.Length)
        ///         {
        ///             int lineEnd = Math.Min(offset + LineLength, base64.Length);
        ///             builder.AppendLine(base64.Substring(offset, lineEnd - offset));
        ///             offset = lineEnd;
        ///         }
        ///     
        ///         builder.AppendLine("-----END CERTIFICATE REQUEST-----");
        ///         return builder.ToString();
        ///     }
        ///   ]]></code>
        /// </remarks>
        public byte[] CreateSigningRequest()
        {
            if (_generator == null)
                throw new InvalidOperationException(SR.Cryptography_CertReq_NoKeyProvided);

            return CreateSigningRequest(_generator);
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest representing the current state
        /// of this object using the provided signature generator.
        /// </summary>
        /// <param name="signatureGenerator">
        ///   A <see cref="X509SignatureGenerator"/> with which to sign the request.
        /// </param>
        public byte[] CreateSigningRequest(X509SignatureGenerator signatureGenerator)
        {
            if (signatureGenerator == null)
                throw new ArgumentNullException(nameof(signatureGenerator));

            X501Attribute[] attributes = Array.Empty<X501Attribute>();

            if (CertificateExtensions.Count > 0)
            {
                attributes = new X501Attribute[] { new Pkcs9ExtensionRequest(CertificateExtensions) };
            }

            var requestInfo = new Pkcs10CertificationRequestInfo(SubjectName, PublicKey, attributes);
            return requestInfo.ToPkcs10Request(signatureGenerator, HashAlgorithm);
        }

        /// <summary>
        /// Create a self-signed certificate using the established subject, key, and optional
        /// extensions.
        /// </summary>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notAfter"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   A constructor was used which did not accept a signing key.
        /// </exception>>
        /// <exception cref="CryptographicException">
        ///   Other errors during the certificate creation process.
        /// </exception>
        public X509Certificate2 CreateSelfSigned(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (_key == null)
                throw new InvalidOperationException(SR.Cryptography_CertReq_NoKeyProvided);

            Debug.Assert(_generator != null);

            byte[] serialNumber = new byte[8];
            RandomNumberGenerator.Fill(serialNumber);

            using (X509Certificate2 certificate = Create(
                SubjectName,
                _generator,
                notBefore,
                notAfter,
                serialNumber))
            {
                RSA rsa = _key as RSA;

                if (rsa != null)
                {
                    return certificate.CopyWithPrivateKey(rsa);
                }

                ECDsa ecdsa = _key as ECDsa;

                if (ecdsa != null)
                {
                    return certificate.CopyWithPrivateKey(ecdsa);
                }

                Gost3410 gost3410 = _key as Gost3410;
                if (gost3410 != null)
                {
                    return certificate.CopyWithPrivateKey(gost3410);
                }
            }

            Debug.Fail($"Key was of no known type: {_key?.GetType().FullName ?? "null"}");
            throw new CryptographicException();
        }

        /// <summary>
        /// Create a certificate using the established subject, key, and optional extensions using
        /// the provided certificate as the issuer.
        /// </summary>
        /// <param name="issuerCertificate">
        ///   An X509Certificate2 instance representing the issuing Certificate Authority (CA).
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   not assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerCertificate"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   The <see cref="X509Certificate2.HasPrivateKey"/> value for <paramref name="issuerCertificate"/> is false.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   The type of signing key represented by <paramref name="issuerCertificate"/> could not be determined.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> is null or has length 0.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="issuerCertificate"/> has a different key algorithm than the requested certificate.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <paramref name="issuerCertificate"/> is an RSA certificate and this object was created via a constructor
        ///   which does not accept a <see cref="RSASignaturePadding"/> value.
        /// </exception>
        public X509Certificate2 Create(
            X509Certificate2 issuerCertificate,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            if (issuerCertificate == null)
                throw new ArgumentNullException(nameof(issuerCertificate));
            if (!issuerCertificate.HasPrivateKey)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerRequiresPrivateKey, nameof(issuerCertificate));
            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (serialNumber == null || serialNumber.Length < 1)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            if (issuerCertificate.PublicKey.Oid.Value != PublicKey.Oid.Value)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_AlgorithmMustMatch,
                        issuerCertificate.PublicKey.Oid.Value,
                        PublicKey.Oid.Value),
                    nameof(issuerCertificate));
            }

            DateTime notBeforeLocal = notBefore.LocalDateTime;
            if (notBeforeLocal < issuerCertificate.NotBefore)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_NotBeforeNotNested,
                        notBeforeLocal,
                        issuerCertificate.NotBefore),
                    nameof(notBefore));
            }

            DateTime notAfterLocal = notAfter.LocalDateTime;

            // Round down to the second, since that's the cert accuracy.
            // This makes one method which uses the same DateTimeOffset for chained notAfters
            // not need to do the rounding locally.
            long notAfterLocalTicks = notAfterLocal.Ticks;
            long fractionalSeconds = notAfterLocalTicks % TimeSpan.TicksPerSecond;
            notAfterLocalTicks -= fractionalSeconds;
            notAfterLocal = new DateTime(notAfterLocalTicks, notAfterLocal.Kind);

            if (notAfterLocal > issuerCertificate.NotAfter)
            {
                throw new ArgumentException(
                    SR.Format(
                        SR.Cryptography_CertReq_NotAfterNotNested,
                        notAfterLocal,
                        issuerCertificate.NotAfter),
                    nameof(notAfter));
            }

            // Check the Basic Constraints and Key Usage extensions to help identify inappropriate certificates.
            // Note that this is not a security check. The system library backing X509Chain will use these same criteria
            // to determine if a chain is valid; and a user can easily call the X509SignatureGenerator overload to
            // bypass this validation.  We're simply helping them at signing time understand that they've
            // chosen the wrong cert.
            var basicConstraints = (X509BasicConstraintsExtension)issuerCertificate.Extensions[Oids.BasicConstraints2];
            var keyUsage = (X509KeyUsageExtension)issuerCertificate.Extensions[Oids.KeyUsage];

            if (basicConstraints == null)
                throw new ArgumentException(SR.Cryptography_CertReq_BasicConstraintsRequired, nameof(issuerCertificate));
            if (!basicConstraints.CertificateAuthority)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerBasicConstraintsInvalid, nameof(issuerCertificate));
            if (keyUsage != null && (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
                throw new ArgumentException(SR.Cryptography_CertReq_IssuerKeyUsageInvalid, nameof(issuerCertificate));

            AsymmetricAlgorithm key = null;
            string keyAlgorithm = issuerCertificate.GetKeyAlgorithm();
            X509SignatureGenerator generator;

            try
            {
                switch (keyAlgorithm)
                {
                    case Oids.Rsa:
                        if (_rsaPadding == null)
                        {
                            throw new InvalidOperationException(SR.Cryptography_CertReq_RSAPaddingRequired);
                        }

                        RSA rsa = issuerCertificate.GetRSAPrivateKey();
                        key = rsa;
                        generator = X509SignatureGenerator.CreateForRSA(rsa, _rsaPadding);
                        break;
                    case Oids.EcPublicKey:
                        ECDsa ecdsa = issuerCertificate.GetECDsaPrivateKey();
                        key = ecdsa;
                        generator = X509SignatureGenerator.CreateForECDsa(ecdsa);
                        break;
                    //begin: gost
                    //case Oids.Gost3410EL:
                    //    Gost3410 gost3410 = issuerCertificate.GetGost3410PrivateKey();
                    //    key = gost3410;
                    //    generator = X509SignatureGenerator.CreateForGost3410(gost3410);
                    //    break;
                    //end: gost
                    default:
                        throw new ArgumentException(
                            SR.Format(SR.Cryptography_UnknownKeyAlgorithm, keyAlgorithm),
                            nameof(issuerCertificate));
                }

                return Create(issuerCertificate.SubjectName, generator, notBefore, notAfter, serialNumber);
            }
            finally
            {
                key?.Dispose();
            }
        }

        /// <summary>
        /// Sign the current certificate request to create a chain-signed or self-signed certificate.
        /// </summary>
        /// <param name="issuerName">The X500DistinguishedName for the Issuer</param>
        /// <param name="generator">
        ///   An <see cref="X509SignatureGenerator"/> representing the issuing certificate authority.
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   The ASN.1 DER-encoded certificate, suitable to be passed to <see cref="X509Certificate2(byte[])"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerName"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="generator"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notBefore"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> is null or has length 0.</exception>
        /// <exception cref="CryptographicException">Any error occurs during the signing operation.</exception>
        public X509Certificate2 Create(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            if (issuerName == null)
                throw new ArgumentNullException(nameof(issuerName));
            if (generator == null)
                throw new ArgumentNullException(nameof(generator));
            if (notAfter < notBefore)
                throw new ArgumentException(SR.Cryptography_CertReq_DatesReversed);
            if (serialNumber == null || serialNumber.Length < 1)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            byte[] signatureAlgorithm = generator.GetSignatureAlgorithmIdentifier(HashAlgorithm);
            AlgorithmIdentifierAsn signatureAlgorithmAsn;

            // Deserialization also does validation of the value (except for Parameters, which have to be validated separately).
            signatureAlgorithmAsn = AlgorithmIdentifierAsn.Decode(signatureAlgorithm, AsnEncodingRules.DER);
            if (signatureAlgorithmAsn.Parameters.HasValue)
            {
                Helpers.ValidateDer(signatureAlgorithmAsn.Parameters.Value);
            }

            TbsCertificateAsn tbsCertificate = new TbsCertificateAsn
            {
                Version = 2,
                SerialNumber = NormalizeSerialNumber(serialNumber),
                SignatureAlgorithm = signatureAlgorithmAsn,
                Issuer = issuerName.RawData,
                SubjectPublicKeyInfo = new SubjectPublicKeyInfoAsn
                {
                    Algorithm = new AlgorithmIdentifierAsn
                    {
                        Algorithm = PublicKey.Oid,
                        Parameters = PublicKey.EncodedParameters.RawData,
                    },
                    SubjectPublicKey = PublicKey.EncodedKeyValue.RawData,
                },
                Validity = new ValidityAsn(notBefore, notAfter),
                Subject = SubjectName.RawData,
            };

            if (CertificateExtensions.Count > 0)
            {
                HashSet<string> usedOids = new HashSet<string>(CertificateExtensions.Count);
                List<X509ExtensionAsn> extensionAsns = new List<X509ExtensionAsn>(CertificateExtensions.Count);

                // An interesting quirk of skipping null values here is that
                // Extensions.Count == 0 => no extensions
                // Extensions.ContainsOnly(null) => empty extensions list

                foreach (X509Extension extension in CertificateExtensions)
                {
                    if (extension == null)
                    {
                        continue;
                    }

                    if (!usedOids.Add(extension.Oid.Value))
                    {
                        throw new InvalidOperationException(
                            SR.Format(SR.Cryptography_CertReq_DuplicateExtension, extension.Oid.Value));
                    }

                    extensionAsns.Add(new X509ExtensionAsn(extension));
                }

                tbsCertificate.Extensions = extensionAsns.ToArray();
            }

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            using (AsnWriter signedWriter = new AsnWriter(AsnEncodingRules.DER))
            {
                tbsCertificate.Encode(writer);

                byte[] encodedTbsCertificate = writer.Encode();
                CertificateAsn certificate = new CertificateAsn
                {
                    TbsCertificate = tbsCertificate,
                    SignatureAlgorithm = signatureAlgorithmAsn,
                    SignatureValue = generator.SignData(encodedTbsCertificate, HashAlgorithm),
                };

                certificate.Encode(signedWriter);
                return new X509Certificate2(signedWriter.Encode());
            }
        }

        private ReadOnlyMemory<byte> NormalizeSerialNumber(byte[] serialNumber)
        {
            if (serialNumber[0] >= 0x80)
            {
                // Keep the serial number unsigned by prepending a zero.
                var newSerialNumber = new byte[serialNumber.Length + 1];
                newSerialNumber[0] = 0;
                serialNumber.CopyTo(newSerialNumber, 1);
                return newSerialNumber;
            }
            else
            {
                // Strip any unnecessary zeros from the beginning.
                int leadingZeros = 0;
                while (leadingZeros < serialNumber.Length - 1 && serialNumber[leadingZeros] == 0 && serialNumber[leadingZeros + 1] < 0x80)
                {
                    leadingZeros++;
                }
                return new ReadOnlyMemory<byte>(serialNumber, leadingZeros, serialNumber.Length - leadingZeros);
            }
        }
    }
}
