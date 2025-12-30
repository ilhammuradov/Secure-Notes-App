package com.secure.notesapp.service;

import com.secure.notesapp.model.AuditLog;
import com.secure.notesapp.model.Note;

import java.util.List;

public interface AuditLogService {
    void logNoteCreation(String user, Note note);

    void logNoteUpdate(String user, Note note);

    void logNoteDeletion(String user, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogsForNoteId(Long id);
}
