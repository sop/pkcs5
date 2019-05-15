<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;

/*
From RFC 2898 - A.3 PBES1:

   For each OID, the parameters field associated with the OID in an
   AlgorithmIdentifier shall have type PBEParameter:

   PBEParameter ::= SEQUENCE {
       salt OCTET STRING (SIZE(8)),
       iterationCount INTEGER }

From RFC 7292 - Appendix C.  Keys and IVs for Password Privacy Mode:

   This standard does not prescribe a length for the salt either.
   Ideally, the salt is as long as the output of the hash function being
   used and consists of completely random bits.

   pkcs-12PbeParams ::= SEQUENCE {
       salt        OCTET STRING,
       iterations  INTEGER
   }
*/

/**
 * Base class for PBES1 encryption scheme.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-6.1
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.3
 * @see https://tools.ietf.org/html/rfc7292#appendix-C
 */
abstract class PBES1AlgorithmIdentifier extends PBEAlgorithmIdentifier
{
    /**
     * Get the hash function used by the scheme.
     *
     * @return HashFunc
     */
    abstract public function hashFunc(): HashFunc;

    /**
     * Get the block cipher algorithm identifier used by the scheme.
     *
     * @return BlockCipherAlgorithmIdentifier
     */
    abstract public function blockCipher(): BlockCipherAlgorithmIdentifier;

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
        $salt = $seq->at(0)->asOctetString()->string();
        $iteration_count = $seq->at(1)->asInteger()->intNumber();
        return new static($salt, $iteration_count);
    }

    /**
     * {@inheritdoc}
     *
     * @return Sequence
     */
    protected function _paramsASN1(): ?Element
    {
        return new Sequence(new OctetString($this->_salt),
            new Integer($this->_iterationCount));
    }
}
