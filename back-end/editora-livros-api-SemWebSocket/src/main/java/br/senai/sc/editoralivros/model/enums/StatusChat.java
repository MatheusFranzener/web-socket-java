package br.senai.sc.editoralivros.model.enums;

public enum StatusChat {
    AUSENTE("away"), OCUPADO("busy"), ONLINE("online"), OFFLINE("offline");
    final String status;
    StatusChat(String status) {
        this.status = status;
    }
}
