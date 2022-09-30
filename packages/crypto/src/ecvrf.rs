use crate::error::{CryptoError, CryptoResult};
use gmp::mpz::Mpz;
use hex::decode;
use sha2::{Digest, Sha512};

lazy_static! {
    static ref SUITE_STRING: Vec<u8> = decode("04").unwrap();
    static ref BITS: usize = 256;
    static ref PRIME: Mpz =
        "57896044618658097711785492504343953926634992332820282019728792003956564819949"
            .parse::<Mpz>()
            .unwrap();
    static ref ORDER: Mpz =
        "7237005577332262213973186563042994240857116359379907606001950938285454250989"
            .parse::<Mpz>()
            .unwrap();
    static ref COFACTOR: Mpz = "8".parse::<Mpz>().unwrap();
    static ref TWO_INV: Mpz =
        "28948022309329048855892746252171976963317496166410141009864396001978282409975"
            .parse::<Mpz>()
            .unwrap();
    static ref II: Mpz =
        "19681161376707505956807079304988542015446066515923890162744021073123829784752"
            .parse::<Mpz>()
            .unwrap();
    static ref A: Mpz = "486662".parse::<Mpz>().unwrap();
    static ref D: Mpz =
        "37095705934669439343138083508754565189542113879843219016388785533085940283555"
            .parse::<Mpz>()
            .unwrap();
    static ref SQRT_MINUS_A_PLUS_2: Mpz =
        "6853475219497561581579357271197624642482790079785650197046958215289687604742"
            .parse::<Mpz>()
            .unwrap();
    static ref BASE_X: Mpz =
        "15112221349535400772501151409588531511454012693041857206046113283949847762202"
            .parse::<Mpz>()
            .unwrap();
    static ref BASE_Y: Mpz =
        "46316835694926478169428394003475163141307993866256225615783033603165251855960"
            .parse::<Mpz>()
            .unwrap();
    static ref BASE: (Mpz, Mpz) = (
        "15112221349535400772501151409588531511454012693041857206046113283949847762202"
            .parse::<Mpz>()
            .unwrap(),
        "46316835694926478169428394003475163141307993866256225615783033603165251855960"
            .parse::<Mpz>()
            .unwrap()
    );
}

fn x_recover(y: &Mpz) -> Mpz {
    let xx = (y * y - 1) * inverse(&((&*D) * (y * y) + 1));
    let mut x = Mpz::from(xx.powm(&((&*PRIME + Mpz::from(3u64)) >> 3), &*PRIME));
    if (&x * &x - xx).modulus(&PRIME) != Mpz::zero() {
        x = (&x * &*II).modulus(&PRIME);
    }
    if &x & Mpz::one() != Mpz::zero() {
        &*PRIME - x
    } else {
        x
    }
}

fn is_on_curve(x: &Mpz, y: &Mpz) -> bool {
    let x_2 = x * x;
    let y_2 = y * y;

    (&y_2 - &x_2 - 1 - x_2 * y_2 * (&*D)).modulus(&PRIME) == Mpz::zero()
}

fn encode_point(p: &(Mpz, Mpz)) -> Vec<u8> {
    let mut q: Mpz = (&p.1 & ((Mpz::one() << 255) - 1)) + ((&p.0 & Mpz::one()) << 255);
    let mut q_bytes_little: Vec<u8> = vec![0; 32];
    for i in 0..32 {
        q_bytes_little[i] = u8::from_str_radix(&(&q & Mpz::from(255)).to_string(), 10).unwrap();
        q >>= 8;
        if q < Mpz::one() {
            break;
        }
    }
    q_bytes_little
}

fn parse_rev_bytes(bz: &[u8]) -> Mpz {
    let mut rv = Vec::<u8>::from(bz);
    rv.reverse();
    Mpz::from(rv.as_slice())
}

fn decode_point(s: &[u8]) -> CryptoResult<(Mpz, Mpz)> {
    if s.len() == 0 {
        return Err(CryptoError::invalid_hash_format());
    }
    let y = parse_rev_bytes(s) & ((Mpz::from(1u64) << 255) - 1);
    let mut x = x_recover(&y);

    if &x & Mpz::one() != Mpz::from(((s.last().unwrap() >> 7u8) & 1) as u32) {
        x = &*PRIME - x;
    }
    if is_on_curve(&x, &y) {
        Ok((x, y))
    } else {
        Err(CryptoError::invalid_point_on_curve())
    }
}

fn inverse(a: &Mpz) -> Mpz {
    a.invert(&*PRIME).unwrap_or(Mpz::one())
}

fn edwards_add(a: &(Mpz, Mpz), b: &(Mpz, Mpz)) -> (Mpz, Mpz) {
    let x1_y2 = &a.0 * &b.1;
    let x2_y1 = &a.1 * &b.0;
    let all = &*D * &x1_y2 * &x2_y1;
    let x3 = (x1_y2 + x2_y1) * inverse(&(1 + &all));
    let y3 = ((&a.0 * &b.0) + (&a.1 * &b.1)) * inverse(&(1 - &all));
    (x3.modulus(&PRIME), y3.modulus(&PRIME))
}

fn scalar_multiply(p: &(Mpz, Mpz), scalar: &Mpz) -> (Mpz, Mpz) {
    if *scalar == Mpz::zero() {
        return (Mpz::zero(), Mpz::one());
    }

    let mut q = p.clone();
    for i in scalar.to_str_radix(2)[1..].chars() {
        q = edwards_add(&q, &q);
        if i == '1' {
            q = edwards_add(&q, &p);
        }
    }
    q
}

fn ecvrf_decode_proof(pi: &[u8]) -> CryptoResult<((Mpz, Mpz), Mpz, Mpz)> {
    let gamma = decode_point(&pi[0..32])?;
    let c = parse_rev_bytes(&pi[32..48]);
    let s = parse_rev_bytes(&pi[48..]);

    Ok((gamma, c, s))
}

fn expand_message_xmd(msg: &[u8]) -> Vec<u8> {
    let dst_prime = vec![
        69, 67, 86, 82, 70, 95, 101, 100, 119, 97, 114, 100, 115, 50, 53, 53, 49, 57, 95, 88, 77,
        68, 58, 83, 72, 65, 45, 53, 49, 50, 95, 69, 76, 76, 50, 95, 78, 85, 95, 4, 40,
    ];
    let msg_prime = [&[0u8; 128], msg, &[0, 48], &[0], &dst_prime].concat();
    Sha512::digest(&[Sha512::digest(&msg_prime).as_slice(), &[1u8], &dst_prime].concat()).to_vec()
}

fn hash_to_field(msg: &[u8]) -> Mpz {
    Mpz::from(&expand_message_xmd(msg)[..48]).modulus(&PRIME)
}

fn ecvrf_hash_to_curve_elligator2_25519(y: &[u8], alpha: &[u8]) -> CryptoResult<Vec<u8>> {
    let u = hash_to_field(&[y, alpha].concat());

    let mut tv1 = &u * &u;
    // tv1 = modulus(&(&Mpz::from(2) * &tv1), &*PRIME);
    tv1 = (Mpz::from(2u64) * tv1).modulus(&PRIME);
    if tv1 == Mpz::from(&*PRIME - 1) {
        tv1 = Mpz::zero();
    }

    let x1 = inverse(&(&tv1 + 1).modulus(&PRIME));
    let x1 = ((-&*A) * &x1).modulus(&PRIME);

    let gx1 = (&x1 + &*A).modulus(&PRIME);
    let gx1 = (&gx1 * &x1).modulus(&PRIME);
    let gx1 = (&gx1 + 1).modulus(&PRIME);
    let gx1 = (&gx1 * &x1).modulus(&PRIME);

    let x2 = (-&x1 - &*A).modulus(&PRIME);

    let gx2 = (&tv1 * &gx1).modulus(&PRIME);

    let e2 = gx1.powm(&(Mpz::from(&*PRIME - 1) >> 1), &*PRIME) <= Mpz::from(1u64);
    let (x, gx) = if e2 { (x1, gx1) } else { (x2, gx2) };

    let edwards_y = (Mpz::from(&x - 1) * inverse(&(&x + 1))).modulus(&PRIME);
    let edwards_y_rev: Vec<u8> = Vec::from(&edwards_y).into_iter().rev().collect();
    let mut h_prelim = decode_point(edwards_y_rev.as_slice())?;
    let y_coordinate = ((&*SQRT_MINUS_A_PLUS_2 * &x) * inverse(&h_prelim.0)).modulus(&PRIME);

    if (&y_coordinate * &y_coordinate).modulus(&PRIME) != gx {
        return Err(CryptoError::generic_err("xx"));
    }

    let e3 = u8::from_str_radix(&(&y_coordinate & Mpz::one()).to_string(), 10).unwrap() == 1u8;
    if e2 ^ e3 {
        h_prelim.0 = -h_prelim.0.modulus(&PRIME);
    }

    Ok(encode_point(&scalar_multiply(&h_prelim, &*COFACTOR)))
}

fn ecvrf_hash_points(p1: &(Mpz, Mpz), p2: &(Mpz, Mpz), p3: &(Mpz, Mpz), p4: &(Mpz, Mpz)) -> Mpz {
    let s_string = [
        &SUITE_STRING[..],
        &vec![2u8][..],
        &encode_point(p1)[..],
        &encode_point(p2)[..],
        &encode_point(p3)[..],
        &encode_point(p4)[..],
        &vec![0u8][..],
    ]
    .concat();

    let c_string = Sha512::digest(&s_string);
    let mut truncated_c_string: Vec<u8> = Vec::new();
    truncated_c_string.extend(c_string[0..16].iter().rev());

    Mpz::from(truncated_c_string.as_slice())
}

pub fn ecvrf_verify(y: &[u8], pi: &[u8], alpha: &[u8]) -> CryptoResult<bool> {
    if y.len() != 32 {
        return Err(CryptoError::invalid_pubkey_format());
    }

    if pi.len() != 80 {
        return Err(CryptoError::invalid_proof_format());
    }

    let (gamma, c, s) = ecvrf_decode_proof(pi)?;

    let h = ecvrf_hash_to_curve_elligator2_25519(y, alpha)?;
    let y_point = decode_point(y)?;

    let h_point = decode_point(&h)?;

    let s_b = scalar_multiply(&*BASE, &s);
    let c_y = scalar_multiply(&y_point, &c);
    let nc_y = (&*PRIME - c_y.0, c_y.1);
    let u = edwards_add(&s_b, &nc_y);

    let s_h = scalar_multiply(&h_point, &s);
    let c_g = scalar_multiply(&gamma, &c);
    let nc_g = (&*PRIME - c_g.0, c_g.1);
    let v = edwards_add(&nc_g, &s_h);

    let cp = ecvrf_hash_points(&h_point, &gamma, &u, &v);

    Ok(c == cp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;

    #[test]
    fn hash_test() {
        assert_eq!(
            encode(Sha512::digest(&[
                1u8, 2u8, 4u8, 8u8, 16u8, 32u8, 64u8, 128u8, 255u8
            ])),
            "4c506ee4b2f5e349ef7d7a801a2cdaf7a265d23bc04a67acfdde1a9f46aac3fb6c25e9d87ce835328f95627c411c22e016edc142bd7df26d2d09bcff6cd8563c"
        );
    }

    #[test]
    fn is_on_curve_test() {
        assert_eq!(is_on_curve(&Mpz::from(0u64), &Mpz::from(1u64)), true);
        assert_eq!(
            is_on_curve(
                &"2467584584982761739087903239975580076073426676744013905948960903141708961180"
                    .parse::<Mpz>()
                    .unwrap(),
                &"4882184778386801025813782108981700325881234329435150280746293678017607916296"
                    .parse::<Mpz>()
                    .unwrap()
            ),
            true
        );
        assert_eq!(
            is_on_curve(
                &"2467584584982761739087903239975580076073426676744013905948960903141708961180"
                    .parse::<Mpz>()
                    .unwrap(),
                &"4882184778386801025813782108981700325881234329435150280746293678017607916295"
                    .parse::<Mpz>()
                    .unwrap()
            ),
            false
        );
        assert_eq!(
            is_on_curve(
                &"2467584584982761739087903239975580076073426676744013905948960903141708961181"
                    .parse::<Mpz>()
                    .unwrap(),
                &"4882184778386801025813782108981700325881234329435150280746293678017607916296"
                    .parse::<Mpz>()
                    .unwrap()
            ),
            false
        );
    }

    #[test]
    fn x_recover_test() {
        assert_eq!(x_recover(&"1".parse::<Mpz>().unwrap()), "0".parse::<Mpz>().unwrap());
        assert_eq!(
            x_recover(&"1000000".parse::<Mpz>().unwrap()),
            "42264365937216995767569786311423113212193185317045903349677162665330205787882"
                .parse::<Mpz>()
                .unwrap()
        );
        assert_eq!(
            x_recover(
                &"5490344842503262896049970157107921391700051501439740859138324399589050432176"
                    .parse::<Mpz>()
                    .unwrap()
            ),
            "40693201237000043021686838142473729874979326212385650705970612165939555930168"
                .parse::<Mpz>()
                .unwrap()
        );
    }

    #[test]
    fn encode_point_test() {
        assert_eq!(
            encode_point(&(Mpz::from(0), Mpz::from(1))),
            decode("0100000000000000000000000000000000000000000000000000000000000000").unwrap()
        );
        assert_eq!(
            encode_point(&(
                "5490344842503262896049970157107921391700051501439740859138324399589050432176"
                    .parse::<Mpz>()
                    .unwrap(),
                "6892623829087957149769104661949562962747386908121354426791544695725788966110"
                    .parse::<Mpz>()
                    .unwrap()
            )),
            decode("de2c8f6440ccc8b39a44cbb881a0c8ba2be8082f641e285e049c24033b163d0f").unwrap()
        );
        assert_eq!(
            encode_point(&(
                "11765910627670138205555954470128887569457785139558335884609577674421928602465"
                    .parse::<Mpz>()
                    .unwrap(),
                "18209892540234382838474494422429649302902580183111935078055540371838462697257"
                    .parse::<Mpz>()
                    .unwrap()
            )),
            decode("299f6d20010556799ff82f2ad721bd15732f7533cfc6ad8bf333cd22166f42a8").unwrap()
        );
    }

    #[test]
    fn decode_point_test() {
        assert_eq!(
            decode_point(
                &decode("0100000000000000000000000000000000000000000000000000000000000000")
                    .unwrap()
            )
            .unwrap(),
            ("0".parse::<Mpz>().unwrap(), "1".parse::<Mpz>().unwrap())
        );
        assert_eq!(
            decode_point(
                &decode("7b0f068bdde1d396d95b97579ed07cc9cabc5af128b7fa3338f7aca485dc170b")
                    .unwrap()
            )
            .unwrap(),
            (
                "18738815168440011986408904409747661355966848393371742103586138146960616269896"
                    .parse::<Mpz>()
                    .unwrap(),
                "5017600804117403562852659704574511322216896914205922652106168593697487589243"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
        assert_eq!(
            decode_point(
                &decode("299f6d20010556799ff82f2ad721bd15732f7533cfc6ad8bf333cd22166f42a8")
                    .unwrap()
            )
            .unwrap(),
            (
                "11765910627670138205555954470128887569457785139558335884609577674421928602465"
                    .parse::<Mpz>()
                    .unwrap(),
                "18209892540234382838474494422429649302902580183111935078055540371838462697257"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn ecvrf_decode_proof_test() {
        assert_eq!(
            ecvrf_decode_proof(
                &decode("a80954531c41b09280438b805fb8264e20791a0fd011a18f6def7b9cc48315c9f4b41e93d8f4140c1ffc917c67640a45c66e7ce47d754462ab40aa0cce09c11b0234c0a8ba265e5fd27ed1d67bc4a701")
                    .unwrap()
            )
            .unwrap(),
            (
                (
                    "27697607651988823115975462172016124959043654960543528824774351294042131512091"
                        .parse::<Mpz>()
                        .unwrap(),
                    "33056851164339470258906459114062521442851091569965281854821725995490451130792"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                "91770691117758273713681408009594385652"
                .parse::<Mpz>()
                .unwrap(),
                "748732389381679406359389955750217672883708317852412390845739987821316042438"
                .parse::<Mpz>()
                .unwrap()
            )
        );
        assert_eq!(
            ecvrf_decode_proof(
                &decode("9061d3a7c68c64efecda0463eb2163ef7793d7049785510b07e3c381f2bbdd62e11d9b22504c906a80b74cff39ccf52389c1cc3b9fc5c7c3a5a716cbac23541a8267a18750ca7f1f26b9ef4dcb226a0f")
                    .unwrap()
            )
            .unwrap(),
            (
                (
                    "20145088686991237763563330138422416133011020304089967570913862140895427216188"
                        .parse::<Mpz>()
                        .unwrap(),
                    "44718429527015941074873329327942383821260886483403263181075854270961588330896"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                "47799234789388919003118978975460433377"
                .parse::<Mpz>()
                .unwrap(),
                "6972218658068131753903599998180446075911404073082034377012199676502466150793"
                .parse::<Mpz>()
                .unwrap()
            )
        );
    }

    #[test]
    fn ecvrf_hash_points_test() {
        assert_eq!(
            ecvrf_hash_points(
                &(Mpz::from(1), Mpz::from(2)),
                &(Mpz::from(3), Mpz::from(4)),
                &(Mpz::from(5), Mpz::from(6)),
                &(Mpz::from(7), Mpz::from(8)),
            ),
            "161209729549110407160776210096078431864".parse::<Mpz>().unwrap()
        );
        assert_eq!(
            ecvrf_hash_points(
                &(
                    "20145088686991237763563330138422416133011020304089967570913862140895427216188"
                        .parse::<Mpz>()
                        .unwrap(),
                    "44718429527015941074873329327942383821260886483403263181075854270961588330896"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                &(
                    "5313863158657921736192767953913786084044359767756713289178739762614964543209"
                        .parse::<Mpz>()
                        .unwrap(),
                    "50988912630131679334181337403790444623412258884662970567487510258466540553771"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                &(
                    "7107631960465767869535429853349295352031173980104103285621849487667722533297"
                        .parse::<Mpz>()
                        .unwrap(),
                    "42878079319476036336137946623896330600009697504370825498274853352471200872065"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                &(
                    "12156183745850511073089323218562745643254017618359848732866684019020326374996"
                        .parse::<Mpz>()
                        .unwrap(),
                    "28984688919812345790446526728176753506503314096611481498246417562994872970561"
                        .parse::<Mpz>()
                        .unwrap()
                ),
            ),
            "233782579309306465553849508530338471250".parse::<Mpz>().unwrap()
        );
    }

    #[test]
    fn expand_message_xmd_test() {
        assert_eq!(
            expand_message_xmd(&vec![]),
            decode("de5b8109b80da1d4861defe3e20710c8ac2efe65d815bb79d0b0087ddb0667718adb94fa478843979611e80749109ca55881a12b9d64c9ae5f7b36075f8e0354").unwrap()
        );
        assert_eq!(
            expand_message_xmd(&decode("0102040810204080ff").unwrap()),
            decode("916b471e7c4d60e8a4ba6d0310e4e8de5a59d94011c4e8d2843d452a1651b9f854f5582788dec477b3811cd56973dbbba346a98877ffd1b61d045caccbdddbe8").unwrap()
        );
        assert_eq!(
            expand_message_xmd(&decode("756f547ab8accc336a280f96343cfdbe9621935dcb452bba4f3460ef8f090883").unwrap()),
            decode("365d2351f19838da62f7b68464f61e961a01cbc3fdde0099bdc3db6b3a9c3f8d23eeacc1865e570b063263d3e8ded3c4cd4a11566f96ca5f63d06bb65d815bb8").unwrap()
        );
    }

    #[test]
    fn hash_to_field_test() {
        assert_eq!(
            hash_to_field(&vec![]),
            "19984796091926620114398603282246129530205018809106914407141744082303129033320"
                .parse::<Mpz>()
                .unwrap()
        );
        assert_eq!(
            hash_to_field(&decode("0102040810204080ff").unwrap()),
            "40866905167524404221649250981304847553674991259516901614549124933108104064175"
                .parse::<Mpz>()
                .unwrap()
        );
        assert_eq!(
            hash_to_field(
                &decode("6073bd567edb2e1d6ef03cb70a54017ffd5b874b136bbbddfbc5a8af6606b697")
                    .unwrap(),
            ),
            "42190151610809284644600066009282933920020180701265092905748556772002395560942"
                .parse::<Mpz>()
                .unwrap()
        );
        assert_eq!(
            hash_to_field(
                &decode("1152c7e217f100d85a6b7e51cb8e6c838a8fc8c95a5ab43ac7412a085cd67307431cd149b898b98c017fe1003bf848ad1dc2254b093497bfab90159ea54c5559")
                    .unwrap(),
            ),
            "7289615016767941863395051431412729080032480398674317575538643993554362504793"
                .parse::<Mpz>()
                .unwrap()
        );
    }

    #[test]
    fn ecvrf_hash_to_curve_elligator2_25519_test() {
        assert_eq!(
            ecvrf_hash_to_curve_elligator2_25519(&[], &[]).unwrap(),
            decode("0a9bd6360ece6617949a7cb1a1cd215c9c274d1bcc4dcd91d2a647e0734f58c9").unwrap()
        );
        assert_eq!(
            ecvrf_hash_to_curve_elligator2_25519(
                &decode("b47b98eec6e520da81cfd6102c92d66190d572ef278898cfc148b284df52381f")
                    .unwrap(),
                &[1, 2, 3]
            )
            .unwrap(),
            decode("51c6d59d27fdb0bc0da54636ee9ab6bae0bf9ef46a41cacf976a5abc0d854ccc").unwrap()
        );
        assert_eq!(
            ecvrf_hash_to_curve_elligator2_25519(
                &decode("6ee44650273767d0596c7c0e631861a36a34274503b7958969a445e6962ea738").unwrap(),
                &decode("fcfb5ff956e3587cd345e15ab63a02e1b1943d9243befd1c5e03b108f04bc34fdc04a725790d455ae5fb03266afa7c962d4358b466dd8b03a988e9df039b8ace").unwrap()
            ).unwrap(),
            decode("99cfaaa3a43dcd5168cc4730afca6e9685987c0735e6340acfe3db6f72fdd949").unwrap()
        );
        assert_eq!(
            ecvrf_hash_to_curve_elligator2_25519(
                &decode("ecb8ff918f05ebf44ba5bf58867d157372a046a15a96cca44450a94cfed8855ff01cc75816ec3380f7bc4d84a7c1b9df843eaaa5e1d6114b8be13042b454661f").unwrap(),
                &decode("954941e702b3825279370625925250c4110f74d4c022fcfcb90aac995561986424928feab8931d4d1b57d63402c7e307b02095e63773315c3e1fd36ae8e8f1dd").unwrap()
            ).unwrap(),
                decode("ec841063044dc0e1066a4838e526d373008315224697ce5b9497e1faf6deed91").unwrap()
        );
    }

    #[test]
    fn inverse_test() {
        let a = "115792089237316195423570234324123".parse::<Mpz>().unwrap();
        let b = "50185070121833820750509717279311425478202465867786279873084127885179732477785"
            .parse::<Mpz>()
            .unwrap();
        assert_eq!(b, inverse(&a));
    }

    #[test]
    fn ecc_sqrt_test() {
        assert_eq!(
            "35634419551235720116798594689937697774970528779494777598852457192116356634056"
                .parse::<Mpz>()
                .unwrap(),
            x_recover(
                &"50185070121833820750509717279311425478202465867786279873084127885179732477785"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
        assert_eq!(
            "53301587420761876222207658879710286820900298918325969647217375986994648841896"
                .parse::<Mpz>()
                .unwrap(),
            x_recover(&"3185713857305035135".parse::<Mpz>().unwrap())
        );
        assert_eq!(
            "46177144718970195273346399805952030171392250782719158809116863111243864153332"
                .parse::<Mpz>()
                .unwrap(),
            x_recover(&"87305764600495522745247520759120714246727049616".parse::<Mpz>().unwrap())
        );
    }

    #[test]
    fn edwards_add_test() {
        assert_eq!(
            edwards_add(&(Mpz::from(1), Mpz::from(2)), &(Mpz::from(3), Mpz::from(4)),),
            (
                "30669472807527669052310166413469871322722837873560156671152128699509420332835"
                    .parse::<Mpz>()
                    .unwrap(),
                "32803760088457211740806219601341938367891502708272204402052114923463521408048"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
        assert_eq!(
            edwards_add(
                &(
                    "105245200036929210524520003692921052452000369292".parse::<Mpz>().unwrap(),
                    "636368388952114463636838895211446363683889521144".parse::<Mpz>().unwrap()
                ),
                &(
                    "365761262312465236576126231246523657612623124652".parse::<Mpz>().unwrap(),
                    "599638831716981459963883171698145996388317169814".parse::<Mpz>().unwrap()
                ),
            ),
            (
                "16094028690776613779404630311380383789228303041060010793878272985304591730114"
                    .parse::<Mpz>()
                    .unwrap(),
                "56509461539446191492739335780640787740284013129997346250692191322113562145891"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn scalar_multiply_test() {
        assert_eq!(
            scalar_multiply(
                &(
                    "2504841017466682250484101746668225048410174666822504841017466682"
                        .parse::<Mpz>()
                        .unwrap(),
                    "1956113754237990195611375423799019561137542379901956113754237990"
                        .parse::<Mpz>()
                        .unwrap()
                ),
                &"7126414032541130712641403254113071264140325411307126414032541130"
                    .parse::<Mpz>()
                    .unwrap()
            ),
            (
                "3717741300534171586596133929728979624065571837388221471827653882295568582734"
                    .parse::<Mpz>()
                    .unwrap(),
                "1221637037450835314506423104277906057339963056664048728491680523116867554868"
                    .parse::<Mpz>()
                    .unwrap()
            )
        );
        assert_eq!(
            scalar_multiply(
                &(
                    "2504841017466682250484101746668225048410174666822504841017466682"
                        .parse::<Mpz>()
                        .unwrap(),
                    "1513453546461956113754237990195611375423799019561137542379901956113754237990"
                        .parse::<Mpz>()
                        .unwrap(),
                ),
                &"74830380039917927238342598863222899552394587271096264578218486964046080567388"
                    .parse::<Mpz>()
                    .unwrap(),
            ),
            (
                "10451491913815505047931853002078552559328154600536681248542806488509264630860"
                    .parse::<Mpz>()
                    .unwrap(),
                "1891777415277742323394479244063570290330034114551949119047672059968424552778"
                    .parse::<Mpz>()
                    .unwrap(),
            )
        );

        assert_eq!(
            scalar_multiply(
                &(
                    "41580769168035012703902357280663015773275161554063216603182338549261711251193"
                        .parse::<Mpz>()
                        .unwrap(),
                    "24911656077204456209601399282188369610223880089588176348139024489849710828841"
                        .parse::<Mpz>()
                        .unwrap(),
                ),
                &"112366451224199189657043841110239819447199235354327421131306119208159432979989"
                    .parse::<Mpz>()
                    .unwrap(),
            ),
            (
                "8072112576901302001883587473420904198649999849925609514862948818584399467310"
                    .parse::<Mpz>()
                    .unwrap(),
                "35299203632341130723598861202244935989969207066742744119141421954087584890438"
                    .parse::<Mpz>()
                    .unwrap(),
            )
        );
    }

    #[test]
    fn ecvrf_verify_from_draft09_test() {
        assert_eq!(
            ecvrf_verify(
                &decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap(),
                &decode("7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f25898f6bd7d4ed4c75f0282b0f7bb9d0e61b387b76db60b3cbf34bf09109ccb33fab742a8bddc0c8ba3caf5c0b75bb04").unwrap(),
                &[]
            ).unwrap(),
            true
        );
        assert_eq!(
            ecvrf_verify(
                &decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                    .unwrap(),
                &decode("47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef9bf1a234f833f72d8fff36075fd9b836da28b5569e74caa418bae7ef521f2ddd35f5727d271ecc70b4a83c1fc8ebc40c").unwrap(),
                &[114]
            ).unwrap(),
            true
        );
        assert_eq!(
            ecvrf_verify(
                &decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                    .unwrap(),
                &decode("926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce6187befa109606682503b3a1424f0f729ca0418099fbd86a48093e6a8de26307b8d93e02da927e6dd5b73c8f119aee0f").unwrap(),
                &[175, 130]
            ).unwrap(),
            true
        );
    }

    #[test]
    fn ecvrf_verify_additional_test() {
        assert_eq!(
            ecvrf_verify(
                &decode("d4e03360381b0b07bb005090a389de57542e01a3e33fea4340ddcd5059016670")
                    .unwrap(),
                &decode("a80954531c41b09280438b805fb8264e20791a0fd011a18f6def7b9cc48315c9f4b41e93d8f4140c1ffc917c67640a45c66e7ce47d754462ab40aa0cce09c11b0234c0a8ba265e5fd27ed1d67bc4a701").unwrap(),
                &decode("c3f2b31660de8bc95902b9103262cdb941f77376f5d3dbb7a3d5a387797f")
                    .unwrap(),
            ).unwrap(),
            true
        );
        assert_eq!(
            ecvrf_verify(
                &decode("8dc04595b4799e105f3f299457f571c2be1dfef3931549bba440bc27410806ce")
                    .unwrap(),
                &decode("6cff0b3296e553becea46a815e5f4f1a6e56e671ec52d0dda9dba5ebe7d700e7aacd4ec879ec71a4147ce578d677677ce477dc773f7534a44b9c1830b782f128fff3c2d789ea7652894335db46c18a0e").unwrap(),
                &decode("2e98dccaadc86adbed25801a9a9dcfa6264319ddafe83a89c51f3c6d199d")
                    .unwrap(),
            ).unwrap(),
            true
        );
        assert_eq!(
            ecvrf_verify(
                &decode("e6e798f938b551b606cc9abd558c7d1b38d6d58cb7c8dff62abb4e876dd8c7e5")
                    .unwrap(),
                &decode("f34ef549e6acdcc2d485acf7257bdde249e7ad8fa63f067045b5e869b454fdf2787d800dc218964a66a61c17d762dbc866027ff82bbdc3cb49024113a5a29ed233000d9c3fd73b9b72f0eebd4e20770e").unwrap(),
                &decode("8ccbd82f7ff2b38c6d48d01e481b2d4faf7171805fd7f2d39ef4c4f19b9496e81dab81")
                    .unwrap(),
            ).unwrap(),
            true
        );
        assert_eq!(
            ecvrf_verify(
                &decode("b78bfbbd68ca4915c854a4cc04afa79ab35a393931a5388db306da94a9d0d2c3")
                    .unwrap(),
                &decode("8057fc57942da97027ea37353d22c6e63c81961574424e1f60e406a0791d6a460700700bf2926d16872a7e8240898db4f239e0f68473503c61f74f19a27c182373ec99ab5c871b2305f5d7bd1c95da08").unwrap(),
                &decode("34a11e19fd3650e9b7818fc33a1e0fc02c44557ac8")
                    .unwrap(),
            ).unwrap(),
            true
        );
    }
}
