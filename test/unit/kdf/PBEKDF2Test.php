<?php
use Sop\PKCS5\PBEKD\PBEKDF;
use Sop\PKCS5\PBEKD\PBEKDF2;
use Sop\PKCS5\PRF\HMACSHA1;

/**
 * @group pbe
 * @group kdf
 */
class PBEKDF2Test extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return PBEKDF
     */
    public function testCreate()
    {
        $kdf = new PBEKDF2(new HMACSHA1());
        $this->assertInstanceOf(PBEKDF::class, $kdf);
        return $kdf;
    }
    
    /**
     * @depends testCreate
     *
     * @param PBEKDF $kdf
     */
    public function testDerive(PBEKDF $kdf)
    {
        $key = $kdf->derive("password", "salt", 8, 16);
        $this->assertEquals(16, strlen($key));
    }
    
    /**
     * @depends testCreate
     *
     * @param PBEKDF $kdf
     */
    public function testDeriveLong(PBEKDF $kdf)
    {
        $key = $kdf->derive("password", "salt", 8, 256);
        $this->assertEquals(256, strlen($key));
    }
}
