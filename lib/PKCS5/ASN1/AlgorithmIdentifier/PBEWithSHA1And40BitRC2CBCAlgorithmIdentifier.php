<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\SHA1;

/**
 * Algorithm identifier for password-based encryption scheme with SHA-1 and
 * 40-bit RC2.
 *
 * @see https://tools.ietf.org/html/rfc7292#appendix-C
 */
class PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier extends PBES1PKCS12AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt            Salt
     * @param int    $iteration_count Iteration count
     */
    public function __construct(string $salt, int $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = self::OID_PBE_WITH_SHA1_AND_RC2_40_CBC;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'pbewithSHAAnd40BitRC2-CBC';
    }

    /**
     * {@inheritdoc}
     */
    public function hashFunc(): HashFunc
    {
        return new SHA1();
    }

    /**
     * {@inheritdoc}
     */
    public function blockCipher(): BlockCipherAlgorithmIdentifier
    {
        return new RC2CBCAlgorithmIdentifier(40);
    }
}
