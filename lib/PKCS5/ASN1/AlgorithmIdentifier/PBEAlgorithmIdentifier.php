<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\EncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * Base class for Password-Based Cryptography schemes.
 *
 * @see https://tools.ietf.org/html/rfc2898
 */
abstract class PBEAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements EncryptionAlgorithmIdentifier
{
    const OID_PBE_WITH_MD2_AND_DES_CBC = '1.2.840.113549.1.5.1';
    const OID_PBE_WITH_MD5_AND_DES_CBC = '1.2.840.113549.1.5.3';
    const OID_PBE_WITH_MD2_AND_RC2_CBC = '1.2.840.113549.1.5.4';
    const OID_PBE_WITH_MD5_AND_RC2_CBC = '1.2.840.113549.1.5.6';
    const OID_PBE_WITH_MD5_AND_XOR = '1.2.840.113549.1.5.9';
    const OID_PBE_WITH_SHA1_AND_DES_CBC = '1.2.840.113549.1.5.10';
    const OID_PBE_WITH_SHA1_AND_RC2_CBC = '1.2.840.113549.1.5.11';
    const OID_PBES2 = '1.2.840.113549.1.5.13';
    const OID_PBMAC1 = '1.2.840.113549.1.5.14';

    // PKCS #12 algorithms
    const OID_PBE_WITH_SHA1_AND_RC4_128 = '1.2.840.113549.1.12.1.1';
    const OID_PBE_WITH_SHA1_AND_RC4_40 = '1.2.840.113549.1.12.1.2';
    const OID_PBE_WITH_SHA1_AND_3KEY_3DES_CBC = '1.2.840.113549.1.12.1.3';
    const OID_PBE_WITH_SHA1_AND_2KEY_3DES_CBC = '1.2.840.113549.1.12.1.4';
    const OID_PBE_WITH_SHA1_AND_RC2_128_CBC = '1.2.840.113549.1.12.1.5';
    const OID_PBE_WITH_SHA1_AND_RC2_40_CBC = '1.2.840.113549.1.12.1.6';

    /**
     * Salt.
     *
     * @var string
     */
    protected $_salt;

    /**
     * Iteration count.
     *
     * @var int
     */
    protected $_iterationCount;

    /**
     * Constructor.
     *
     * @param string $salt
     * @param int    $iteration_count
     */
    public function __construct(string $salt, int $iteration_count)
    {
        $this->_salt = $salt;
        $this->_iterationCount = $iteration_count;
    }

    /**
     * @param Sequence $seq
     *
     * @return AlgorithmIdentifier
     */
    public static function fromASN1(Sequence $seq): AlgorithmIdentifier
    {
        return (new AlgorithmIdentifierFactory(
            new PKCS5AlgorithmIdentifierProvider()))->parse($seq);
    }

    /**
     * Get salt.
     *
     * @return string
     */
    public function salt(): string
    {
        return $this->_salt;
    }

    /**
     * Get iteration count.
     *
     * @return int
     */
    public function iterationCount(): int
    {
        return $this->_iterationCount;
    }
}
