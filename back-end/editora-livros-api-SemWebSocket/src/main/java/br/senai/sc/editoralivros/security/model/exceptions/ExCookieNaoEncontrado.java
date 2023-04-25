package br.senai.sc.editoralivros.security.model.exceptions;

public class ExCookieNaoEncontrado extends Exception{
    public ExCookieNaoEncontrado() {
        super("Cookie não encontrado!");
    }
}
