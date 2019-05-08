<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/*
From RFC 2898 - A.4 PBES2:

The parameters field associated with this OID in an
AlgorithmIdentifier shall have type PBES2-params:

PBES2-params ::= SEQUENCE {
    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
*/

/**
 * Algorithm identifier for PBES2 encryption scheme.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-6.2
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.4
 */
class PBES2AlgorithmIdentifier extends PBEAlgorithmIdentifier
{
    /**
     * PBKDF2 algorithm identifier.
     *
     * @var PBKDF2AlgorithmIdentifier
     */
    protected $_kdf;

    /**
     * Encryption algorithm identifier.
     *
     * @var BlockCipherAlgorithmIdentifier
     */
    protected $_es;

    /**
     * Constructor.
     *
     * @param PBKDF2AlgorithmIdentifier      $kdf
     * @param BlockCipherAlgorithmIdentifier $es
     */
    public function __construct(PBKDF2AlgorithmIdentifier $kdf,
        BlockCipherAlgorithmIdentifier $es)
    {
        parent::__construct($kdf->salt(), $kdf->iterationCount());
        $this->_oid = self::OID_PBES2;
        $this->_kdf = $kdf;
        $this->_es = $es;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'pkcs5PBES2';
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromASN1Params(
        ?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (!isset($params)) {
            throw new \UnexpectedValueException('No parameters.');
        }
        $seq = $params->asSequence();
        $kdf = PBKDF2AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
        // ensure we got proper key derivation function algorithm
        if (!($kdf instanceof PBKDF2AlgorithmIdentifier)) {
            throw new \UnexpectedValueException(
                'KDF algorithm ' . $kdf->oid() . ' not supported.');
        }
        $es = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
        // ensure we got proper encryption algorithm
        if (!($es instanceof BlockCipherAlgorithmIdentifier)) {
            throw new \UnexpectedValueException(
                'ES algorithm ' . $es->oid() . ' not supported.');
        }
        return new self($kdf, $es);
    }

    /**
     * Get key derivation function algorithm identifier.
     *
     * @return PBKDF2AlgorithmIdentifier
     */
    public function kdfAlgorithmIdentifier(): PBKDF2AlgorithmIdentifier
    {
        return $this->_kdf;
    }

    /**
     * Get encryption scheme algorithm identifier.
     *
     * @return BlockCipherAlgorithmIdentifier
     */
    public function esAlgorithmIdentifier(): BlockCipherAlgorithmIdentifier
    {
        return $this->_es;
    }

    /**
     * {@inheritdoc}
     *
     * @return Sequence
     */
    protected function _paramsASN1(): ?Element
    {
        return new Sequence($this->_kdf->toASN1(), $this->_es->toASN1());
    }
}
