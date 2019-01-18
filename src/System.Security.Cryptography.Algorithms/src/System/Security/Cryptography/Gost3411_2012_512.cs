using Internal.Cryptography;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Абстрактный базовый класс для всех реализаций алгоритма ГОСТ Р 34.11-2012 512.
    /// Все реализации алгоритма ГОСТ Р 34.11-2012 512  должны быть отнаследованы от данного класса.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>Создание наследников данного класса позволяет создать конкретную 
    /// реализацию алгоритма ГОСТ Р 34.11-2012 512.</para>
    /// <para>Основное применение данного класса, это идентификация алгоритма 
    /// ГОСТ Р 34.11-2012 512 в иерархии криптографических алгоритмов.</para>
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\DocBlock" name="HashBuffer" region="HashBuffer">
    /// Пример, вычисляющий хэш по алгоритму ГОСТ Р 34.11-2012 512 при помощи класса
    /// <see cref="Gost3411_2012_512CryptoServiceProvider"/>, унаследованного от 
    /// Gost3411_2012_512. В примере предполагается, что ранее определена константа 
    /// DATA_SIZE.
    /// </doc-sample>
    /// 
    /// <basedon cref="System.Security.Cryptography.SHA1"/>
    public abstract class Gost3411_2012_512 : HashAlgorithm
    {
        internal const int GOST3411_2012_512_SIZE = 512;

        public static new Gost3411_2012_512 Create() => new Implementation();

        public static new Gost3411_2012_512 Create(string hashName) => (Gost3411_2012_512)CryptoConfig.CreateFromName(hashName);

        private sealed class Implementation : Gost3411_2012_512
        {
            private readonly HashProvider _hashProvider;

            public Implementation()
            {
                _hashProvider = HashProviderDispenser.CreateHashProvider(HashAlgorithmNames.GOST3411_2012_512);
                HashSizeValue = GOST3411_2012_512_SIZE;
            }

            protected sealed override void HashCore(byte[] array, int ibStart, int cbSize) =>
                _hashProvider.AppendHashData(array, ibStart, cbSize);

            protected sealed override void HashCore(ReadOnlySpan<byte> source) =>
                _hashProvider.AppendHashData(source);

            protected sealed override byte[] HashFinal() =>
                _hashProvider.FinalizeHashAndReset();

            protected sealed override bool TryHashFinal(Span<byte> destination, out int bytesWritten) =>
                _hashProvider.TryFinalizeHashAndReset(destination, out bytesWritten);

            public sealed override void Initialize()
            {
                // Nothing to do here. We expect HashAlgorithm to invoke HashFinal() and Initialize() as a pair. This reflects the 
                // reality that our native crypto providers (e.g. CNG) expose hash finalization and object reinitialization as an atomic operation.
            }

            protected sealed override void Dispose(bool disposing)
            {
                _hashProvider.Dispose(disposing);
                base.Dispose(disposing);
            }
        }
    }
}
