package br.senai.sc.editoralivros.security.model.exceptions;

public class ExTokenInvalido extends Exception{
    public ExTokenInvalido() {
        super("Token inválido!");
    }
}
