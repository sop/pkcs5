<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PRF;

use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;

/**
 * Base class for pseudorandom functions used in password-based cryptography.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-B.1
 */
abstract class PRF
{
    /**
     * Length of the produced output in bytes.
     *
     * @var int $_length
     */
    protected $_length;
    
    /**
     * Compute pseudorandom value from arguments.
     *
     * @param string $arg1 First argument
     * @param string $arg2 Second argument
     * @return string Output
     */
    abstract public function compute(string $arg1, string $arg2): string;
    
    /**
     * Functor interface.
     *
     * @param string $arg1
     * @param string $arg2
     * @return string
     */
    public function __invoke(string $arg1, string $arg2): string
    {
        return $this->compute($arg1, $arg2);
    }
    
    /**
     * Get output length.
     *
     * @return int
     */
    public function length(): int
    {
        return $this->_length;
    }
    
    /**
     * Mapping from hash algorithm identifier OID to class name.
     *
     * @internal
     * @var array
     */
    const MAP_HASH_OID_TO_CLASS = array(
        /* @formatter:off */
        AlgorithmIdentifier::OID_HMAC_WITH_SHA1 => HMACSHA1::class,
        AlgorithmIdentifier::OID_HMAC_WITH_SHA224 => HMACSHA224::class,
        AlgorithmIdentifier::OID_HMAC_WITH_SHA256 => HMACSHA256::class,
        AlgorithmIdentifier::OID_HMAC_WITH_SHA384 => HMACSHA384::class,
        AlgorithmIdentifier::OID_HMAC_WITH_SHA512 => HMACSHA512::class
        /* @formatter:on */
    );
    
    /**
     * Get PRF by algorithm identifier.
     *
     * @param PRFAlgorithmIdentifier $algo
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromAlgorithmIdentifier(PRFAlgorithmIdentifier $algo): PRF
    {
        $oid = $algo->oid();
        if (array_key_exists($oid, self::MAP_HASH_OID_TO_CLASS)) {
            $cls = self::MAP_HASH_OID_TO_CLASS[$oid];
            return new $cls();
        }
        throw new \UnexpectedValueException(
            "PRF algorithm " . $algo->oid() . " not supported.");
    }
}
