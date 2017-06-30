<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;

/* @formatter:off *//*

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

*//* @formatter:on */

/**
 * Base class for PBES1 encryption scheme.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6.1
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.3
 * @link https://tools.ietf.org/html/rfc7292#appendix-C
 */
abstract class PBES1AlgorithmIdentifier extends PBEAlgorithmIdentifier
{
    /**
     * Get the hash function used by the scheme.
     *
     * @return \Sop\PKCS5\HashFunc\HashFunc
     */
    abstract public function hashFunc();
    
    /**
     * Get the block cipher algorithm identifier used by the scheme.
     *
     * @return \Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier
     */
    abstract public function blockCipher();
    
    /**
     *
     * @param UnspecifiedType $params
     * @throws \UnexpectedValueException
     * @return PBES1AlgorithmIdentifier
     */
    public static function fromASN1Params(UnspecifiedType $params = null)
    {
        if (!isset($params)) {
            throw new \UnexpectedValueException("No parameters.");
        }
        $seq = $params->asSequence();
        $salt = $seq->at(0)
            ->asOctetString()
            ->string();
        $iteration_count = $seq->at(1)
            ->asInteger()
            ->number();
        return new static($salt, $iteration_count);
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    protected function _paramsASN1()
    {
        return new Sequence(new OctetString($this->_salt),
            new Integer($this->_iterationCount));
    }
}
