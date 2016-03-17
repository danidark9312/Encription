package co.com.quipux.utility.security;

public class CorteLinea {
	
	public static void main(String args[]){
		String textoEntrante = ""
				+ "Este es un texto con muchas palabras Este es un texto con muchas palabras  Este es un texto con muchas palabras"
				+ "Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto "
				+ "Este es un texto con muchas palabras Este es un texto con muchas palabras  Este es un texto con muchas palabras"
				+ "Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto "
				+ "Este es un texto con muchas palabras Este es un texto con muchas palabras  Este es un texto con muchas palabras"
				+ "Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto "
				+ "Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto Otro texto "
				+ "Este es un texto con muchas palabras Este es un texto con muchas palabras  Este es un texto con muchas palabras"
				
+ "Este es un texto con muchas palabras Este es un texto con muchas palabras  Este es un texto con muchas palabras"
				+ " Este es un texto con muchas palabras Este es un texto con muchas palabras Este es un texto con muchas palabras";
		
		System.out.println(getMessage(textoEntrante));
	}
	
	private static String getMessage(String entrante){
		StringBuffer bresult = new StringBuffer("");
		StringBuffer bentrante = new StringBuffer(entrante);
		
		while(bentrante.length()>47){
			bresult.append(bentrante.substring(0, 47)+"\n");
			bentrante.delete(0, 47);
		}
		bresult.append(bentrante.toString());
		return bresult.toString();
	}

}
