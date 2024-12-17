pub fn encode_signature_as_der(signature_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(
        signature_bytes.len(),
        64,
        "La firma debe tener 64 bytes: r (32) + s (32)"
    );

    // Divide la firma en r y s
    let (r, s) = signature_bytes.split_at(32);
    let r_der = encode_asn1_integer(r);
    let s_der = encode_asn1_integer(s);

    // Longitud total de la secuencia
    let total_len = r_der.len() + s_der.len();

    // Formato DER para la secuencia
    let mut der = vec![0x30, total_len as u8];
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);

    der
}

pub fn encode_asn1_integer(bytes: &[u8]) -> Vec<u8> {
    let mut integer = bytes.to_vec();

    // Si el byte más significativo (MSB) es >= 0x80, se necesita padding 0x00
    if integer[0] & 0x80 != 0 {
        integer.insert(0, 0x00);
    }

    let mut result = vec![0x02, integer.len() as u8];
    result.extend_from_slice(&integer);

    result
}

pub fn build_script_sig(signature_bytes: &[u8], public_key_bytes: &[u8]) -> Vec<u8> {
    // Paso 1: Codificar la firma como DER
    let mut signature_der = encode_signature_as_der(signature_bytes);

    // Paso 2: Agregar el byte SIGHASH_ALL (0x01)
    signature_der.push(0x01);

    // Paso 3: Codificar la longitud de la firma DER y concatenar
    let mut script_sig = vec![];
    script_sig.push(signature_der.len() as u8); // Longitud de la firma
    script_sig.extend_from_slice(&signature_der); // Firma en formato DER + SIGHASH

    // Paso 4: Codificar la longitud de la clave pública y concatenar
    script_sig.push(public_key_bytes.len() as u8); // Longitud de la clave pública
    script_sig.extend_from_slice(public_key_bytes); // Clave pública comprimida

    script_sig
}
