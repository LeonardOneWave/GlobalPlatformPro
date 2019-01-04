package pro.javacard.gp;

import apdu4j.HexUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.EnumSet;

public class TestSCP02 {

    @Test
    public void testEncryptDataWithDek() throws GPException {
        byte[] clearText = HexUtils.stringToBin("" +
                "CD9A8B15AF570FC173B14C428603556507F3085F59029253D31A539BA57528C4" +
                "7D36255901E4074B27A5FA5A20350CE7FBA87054051D8C6C3B5E3747946AA006" +
                "919D5900CD57C5434AAD99F9B3B12143D079B5BB14DFA8F62073D21490E0957D" +
                "3BBA3A4735DE33B62CC506A4732C6FC97F8F826329AA770E8D709726A8F2517E" +
                "BDADCC04B0BFC3DCC10D57C5EE0C70EE6950AE80AAA659C76B49E72B535FE5B2" +
                "8B1EAA4BD5217325CAEDD8693EB0E475B6969ED9312D82ABB28A69429DEE07BE");
        byte[] expectedCipherText = HexUtils.stringToBin("" +
                "14318DDBC2FB7065355519322246AA734B32BEDDD60F135E88E682F6E62415" +
                "441F5B69583E4EEB74769280E54ECE4B3AB55689B102F1B1327BA01C14B5E9" +
                "75F0BB322AFCB87D3E0D663097B8521C04BFA4E8C90D167124B7E237ADD2E1" +
                "A9FC2F1E6449E4AE35BB40545CE146DA0DFD5C8ED1AEB18AFFD85F3445C937" +
                "606D145884BE30306649114E127C32DFB3AD57B9FA9B5F7357A9DCE93A409A" +
                "396F3FAC830730BBFC50588B954B606D7B9E1DE17E5C733872FD669724ED86" +
                "725965EEABDE");
        byte[] dekKey = HexUtils.stringToBin("9262774C5B5D8E55FA9DFA865283139D");
        EnumSet<GlobalPlatform.APDUMode> secuLevel = EnumSet.of(GlobalPlatform.APDUMode.MAC, GlobalPlatform.APDUMode.ENC);
        SCP0102Wrapper wrapper = new SCP0102Wrapper( new DummyDekSessionKeyProvider(dekKey), 2, secuLevel, null, null, 255);
        byte[] computedCipherText = wrapper.encryptData(clearText);
        Assert.assertArrayEquals(expectedCipherText, computedCipherText);
    }

    @Test
    public void testDecryptDataWithDek() throws GPException {
        byte[] cipherText = HexUtils.stringToBin("" +
                "14318DDBC2FB7065355519322246AA734B32BEDDD60F135E88E682F6E62415" +
                "441F5B69583E4EEB74769280E54ECE4B3AB55689B102F1B1327BA01C14B5E9" +
                "75F0BB322AFCB87D3E0D663097B8521C04BFA4E8C90D167124B7E237ADD2E1" +
                "A9FC2F1E6449E4AE35BB40545CE146DA0DFD5C8ED1AEB18AFFD85F3445C937" +
                "606D145884BE30306649114E127C32DFB3AD57B9FA9B5F7357A9DCE93A409A" +
                "396F3FAC830730BBFC50588B954B606D7B9E1DE17E5C733872FD669724ED86" +
                "725965EEABDE");
        byte[] expectedClearText = HexUtils.stringToBin("" +
                "CD9A8B15AF570FC173B14C428603556507F3085F59029253D31A539BA57528C4" +
                "7D36255901E4074B27A5FA5A20350CE7FBA87054051D8C6C3B5E3747946AA006" +
                "919D5900CD57C5434AAD99F9B3B12143D079B5BB14DFA8F62073D21490E0957D" +
                "3BBA3A4735DE33B62CC506A4732C6FC97F8F826329AA770E8D709726A8F2517E" +
                "BDADCC04B0BFC3DCC10D57C5EE0C70EE6950AE80AAA659C76B49E72B535FE5B2" +
                "8B1EAA4BD5217325CAEDD8693EB0E475B6969ED9312D82ABB28A69429DEE07BE");
        byte[] dekKey = HexUtils.stringToBin("9262774C5B5D8E55FA9DFA865283139D");

        EnumSet<GlobalPlatform.APDUMode> secuLevel = EnumSet.of(GlobalPlatform.APDUMode.MAC, GlobalPlatform.APDUMode.ENC);
        SCP0102Wrapper wrapper = new SCP0102Wrapper( new DummyDekSessionKeyProvider(dekKey), 2, secuLevel, null, null, 255);
        byte[] computedClearText = wrapper.decryptData(cipherText);
        Assert.assertArrayEquals(expectedClearText, computedClearText);
    }

    class DummyDekSessionKeyProvider extends GPSessionKeyProvider {
        private GPKey dek_key = null;

        public DummyDekSessionKeyProvider(GPKey dek_key) {
            this.dek_key = dek_key;
        }

        public DummyDekSessionKeyProvider(byte[] key) {
            this(new GPKey(key, GPKey.Type.DES3));
        }

        @Override
        public boolean init(byte[] atr, byte[] cplc, byte[] kinfo) {
            return false;
        }

        @Override
        public void calculate(int scp, byte[] kdd, byte[] host_challenge, byte[] card_challenge, byte[] ssc) throws GPException {

        }

        @Override
        public GPKey getKeyFor(KeyPurpose p) {
            if(p == KeyPurpose.DEK) {
                return dek_key;
            }
            return null;
        }

        @Override
        public int getID() {
            return 0;
        }

        @Override
        public int getVersion() {
            return 0;
        }
    }
}
