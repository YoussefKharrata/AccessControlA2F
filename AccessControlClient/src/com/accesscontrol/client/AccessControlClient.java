package com.accesscontrol.client;

import javax.smartcardio.*;
import javax.crypto.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.*;
import java.io.*;
import java.text.SimpleDateFormat;

public class AccessControlClient {

    private static final byte[] APPLET_AID = {
        (byte)0x25, (byte)0x25, (byte)0x25, (byte)0x25, (byte)0x25
    };

    private static final byte INS_SET_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_STORE_KEY = (byte) 0x30;
    private static final byte INS_GET_KEY = (byte) 0x40;
    private static final byte INS_GET_USER_ID = (byte) 0x60;

    private static final int SESSION_TIMEOUT = 300;

    private Card card;
    private CardChannel channel;
    private Scanner scanner;
    private AccessLogger logger;
    private SessionManager sessionManager;
    private PINManager pinManager;

    public AccessControlClient() {
        scanner = new Scanner(System.in);
        logger = new AccessLogger();
        sessionManager = new SessionManager(SESSION_TIMEOUT);
        pinManager = new PINManager();
    }

    public static void main(String[] args) {
        AccessControlClient client = new AccessControlClient();
        try {
            client.connectToSimulator();
            client.run();
        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
            e.printStackTrace();
        } finally {
            client.disconnect();
        }
    }

    private void connectToSimulator() throws Exception {
        

        TerminalFactory factory = TerminalFactory.getInstance(
        	    "SocketCardTerminalFactoryType",
        	    List.of(new InetSocketAddress("localhost", 9026)),
        	    "SocketCardTerminalProvider"
        	);


        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals.isEmpty()) {
            throw new CardException("❌ Aucun terminal détecté sur le simulateur.");
        }

        CardTerminal terminal = terminals.get(0);
        System.out.println("✅ Connecté au terminal: " + terminal.getName());

        if (!terminal.waitForCardPresent(5000)) {
            throw new CardException("❌ Aucune carte présente dans le simulateur.");
        }

        card = terminal.connect("*");
        channel = card.getBasicChannel();

        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID)
        );

        if (response.getSW() != 0x9000) {
            throw new CardException("❌ Échec de sélection de l'applet, SW=" + String.format("%04X", response.getSW()));
        }

        System.out.println("✅ Applet sélectionnée avec succès\n");
    }

    /**
     * Boucle principale de l'application
     */
    private void run() throws Exception {
        boolean running = true;
        
        while (running) {
            displayMenu();
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consommer la nouvelle ligne
            
            switch (choice) {
                case 1:
                    initializeUser();
                    break;
                case 2:
                    authenticate();
                    break;
                case 3:
                    displayAccessLogs();
                    break;
                case 4:
                    running = false;
                    System.out.println("Au revoir!");
                    break;
                default:
                    System.out.println("Option invalide\n");
            }
        }
    }
    
    /**
     * Afficher le menu principal
     */
    private void displayMenu() {
        System.out.println("=== SYSTÈME DE CONTRÔLE D'ACCÈS A2F ===");
        System.out.println("1. Initialiser un nouveau badge");
        System.out.println("2. S'authentifier");
        System.out.println("3. Afficher les logs d'accès");
        System.out.println("4. Quitter");
        System.out.print("Choix: ");
    }
    
    /**
     * Initialiser un nouvel utilisateur
     */
    private void initializeUser() throws Exception {
        System.out.println("\n=== INITIALISATION DU BADGE ===");
        
        // Demander l'ID utilisateur
        System.out.print("ID Utilisateur (max 16 caractères): ");
        String userId = scanner.nextLine();
        
        if (userId.length() > 16) {
            userId = userId.substring(0, 16);
        }
        
        // Demander le PIN
        String pin = pinManager.requestNewPIN(scanner);
        
        if (pin == null) {
            System.out.println("Initialisation annulée\n");
            return;
        }
        
        // Envoyer PIN et UserID à la carte
        byte[] pinBytes = pin.getBytes();
        byte[] userIdBytes = userId.getBytes();
        byte[] data = new byte[1 + pinBytes.length + userIdBytes.length];
        
        data[0] = (byte) pinBytes.length;
        System.arraycopy(pinBytes, 0, data, 1, pinBytes.length);
        System.arraycopy(userIdBytes, 0, data, 1 + pinBytes.length, userIdBytes.length);
        
        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_SET_PIN, 0x00, 0x00, data)
        );
        
        if (response.getSW() != 0x9000) {
            System.out.println("Erreur lors de la configuration du PIN\n");
            return;
        }
        
        // Générer et stocker la clé privée
        byte[] privateKey = generatePrivateKey();
        
        // Vérifier le PIN avant de stocker la clé
        response = channel.transmit(
            new CommandAPDU(0x00, INS_VERIFY_PIN, 0x00, 0x00, pinBytes)
        );
        
        if (response.getSW() != 0x9000) {
            System.out.println("Erreur de vérification du PIN\n");
            return;
        }
        
        // Stocker la clé chiffrée
        response = channel.transmit(
            new CommandAPDU(0x00, INS_STORE_KEY, 0x00, 0x00, privateKey)
        );
        
        if (response.getSW() != 0x9000) {
            System.out.println("Erreur lors du stockage de la clé\n");
            return;
        }
        
        System.out.println("✓ Badge initialisé avec succès!");
        System.out.println("Clé privée (hex): " + bytesToHex(privateKey));
        System.out.println("⚠ Conservez cette clé en lieu sûr!\n");
        
        logger.logEvent(userId, "INIT", "Badge initialisé");
    }
    
    /**
     * Processus d'authentification A2F
     */
    private void authenticate() throws Exception {
        System.out.println("\n=== AUTHENTIFICATION A2F ===");
        
        // Récupérer l'ID utilisateur depuis la carte
        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_USER_ID, 0x00, 0x00, 16)
        );
        
        if (response.getSW() != 0x9000) {
            System.out.println("Erreur lors de la lecture de la carte\n");
            return;
        }
        
        String userId = new String(response.getData()).trim();
        System.out.println("Badge détecté: " + userId);
        
        // FACTEUR 1: Vérification du PIN
        System.out.println("\n--- Facteur 1: Vérification PIN ---");
        boolean pinValid = false;
        int attempts = 0;
        int maxAttempts = 3;
        
        while (!pinValid && attempts < maxAttempts) {
            System.out.print("Entrez votre PIN: ");
            String pin = scanner.nextLine();
            
            response = channel.transmit(
                new CommandAPDU(0x00, INS_VERIFY_PIN, 0x00, 0x00, pin.getBytes())
            );
            
            int sw = response.getSW();
            
            if (sw == 0x9000) {
                pinValid = true;
                System.out.println("✓ PIN correct");
            } else if ((sw & 0xFFF0) == 0x63C0) {
                attempts++;
                int remaining = sw & 0x000F;
                System.out.println("✗ PIN incorrect. Tentatives restantes: " + remaining);
                logger.logEvent(userId, "AUTH_FAIL", "PIN incorrect");
            } else if (sw == 0x6983) {
                System.out.println("✗ Carte bloquée. Contactez l'administrateur.\n");
                logger.logEvent(userId, "BLOCKED", "Carte bloquée");
                return;
            } else {
                System.out.println("✗ Erreur de vérification\n");
                return;
            }
        }
        
        if (!pinValid) {
            System.out.println("Nombre maximum de tentatives atteint\n");
            return;
        }
        
        // FACTEUR 2: Vérification de la clé privée
        System.out.println("\n--- Facteur 2: Vérification Clé Privée ---");
        
        response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_KEY, 0x00, 0x00, 16)
        );
        
        if (response.getSW() != 0x9000) {
            System.out.println("✗ Erreur lors de la récupération de la clé\n");
            logger.logEvent(userId, "AUTH_FAIL", "Erreur clé privée");
            return;
        }
        
        byte[] retrievedKey = response.getData();
        
        // Challenge cryptographique simple
        if (verifyCryptographicChallenge(retrievedKey)) {
            System.out.println("✓ Clé privée validée");
            
            // Authentification réussie
            System.out.println("\n✓✓✓ ACCÈS ACCORDÉ ✓✓✓");
            
            // Démarrer une session
            String sessionId = sessionManager.createSession(userId);
            logger.logEvent(userId, "ACCESS_GRANTED", "Accès autorisé - Session: " + sessionId);
            
            // Simuler la gestion de session
            manageSession(userId, sessionId);
            
        } else {
            System.out.println("✗ Clé privée invalide");
            System.out.println("\n✗✗✗ ACCÈS REFUSÉ ✗✗✗\n");
            logger.logEvent(userId, "AUTH_FAIL", "Clé privée invalide");
        }
    }
    
    /**
     * Gérer la session active
     */
    private void manageSession(String userId, String sessionId) throws InterruptedException {
        System.out.println("\n=== SESSION ACTIVE ===");
        System.out.println("Session ID: " + sessionId);
        System.out.println("Timeout: " + SESSION_TIMEOUT + " secondes");
        System.out.println("Appuyez sur Entrée pour terminer la session manuellement...\n");
        
        // Thread pour surveiller le timeout
        Thread timeoutThread = new Thread(() -> {
            try {
                Thread.sleep(SESSION_TIMEOUT * 1000);
                if (sessionManager.isSessionActive(sessionId)) {
                    System.out.println("\n⚠ SESSION EXPIRÉE (timeout)");
                    sessionManager.closeSession(sessionId);
                    logger.logEvent(userId, "SESSION_TIMEOUT", "Session expirée");
                }
            } catch (InterruptedException e) {
                // Thread interrompu
            }
        });
        
        timeoutThread.start();
        scanner.nextLine(); // Attendre l'entrée utilisateur
        
        // Fermer la session manuellement
        if (sessionManager.isSessionActive(sessionId)) {
            sessionManager.closeSession(sessionId);
            System.out.println("Session fermée manuellement");
            logger.logEvent(userId, "SESSION_CLOSED", "Session fermée par l'utilisateur");
        }
        
        timeoutThread.interrupt();
        System.out.println();
    }
    
    /**
     * Afficher les logs d'accès
     */
    private void displayAccessLogs() {
        System.out.println("\n=== LOGS D'ACCÈS ===");
        logger.displayLogs();
        System.out.println();
    }
    
    /**
     * Générer une clé privée aléatoire (16 bytes pour AES-128)
     */
    private byte[] generatePrivateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }
    
    /**
     * Vérifier un challenge cryptographique avec la clé
     */
    private boolean verifyCryptographicChallenge(byte[] key) {
        // Challenge simple: vérifier que la clé a la bonne taille et n'est pas nulle
        if (key == null || key.length != 16) {
            return false;
        }
        
        boolean allZeros = true;
        for (byte b : key) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        
        return !allZeros;
    }
    
    /**
     * Convertir bytes en hexadécimal
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
    
    /**
     * Déconnexion de la carte
     */
    private void disconnect() {
        try {
            if (card != null) {
                card.disconnect(false);
                System.out.println("Carte déconnectée");
            }
        } catch (CardException e) {
            System.err.println("Erreur lors de la déconnexion: " + e.getMessage());
        }
    }
}

/**
 * Gestionnaire de PIN
 */
class PINManager {
    
    public String requestNewPIN(Scanner scanner) {
        System.out.print("Définir un PIN (4-8 chiffres): ");
        String pin = scanner.nextLine();
        
        if (!isValidPIN(pin)) {
            System.out.println("PIN invalide (doit contenir 4-8 chiffres)");
            return null;
        }
        
        System.out.print("Confirmer le PIN: ");
        String confirmPin = scanner.nextLine();
        
        if (!pin.equals(confirmPin)) {
            System.out.println("Les PINs ne correspondent pas");
            return null;
        }
        
        return pin;
    }
    
    private boolean isValidPIN(String pin) {
        if (pin == null || pin.length() < 4 || pin.length() > 8) {
            return false;
        }
        return pin.matches("\\d+");
    }
}

/**
 * Gestionnaire de sessions
 */
class SessionManager {
    
    private Map<String, SessionInfo> activeSessions;
    private int timeoutSeconds;
    
    public SessionManager(int timeoutSeconds) {
        this.activeSessions = new HashMap<>();
        this.timeoutSeconds = timeoutSeconds;
    }
    
    public String createSession(String userId) {
        String sessionId = UUID.randomUUID().toString().substring(0, 8);
        SessionInfo session = new SessionInfo(userId, sessionId, System.currentTimeMillis());
        activeSessions.put(sessionId, session);
        return sessionId;
    }
    
    public boolean isSessionActive(String sessionId) {
        SessionInfo session = activeSessions.get(sessionId);
        if (session == null) {
            return false;
        }
        
        long elapsed = System.currentTimeMillis() - session.startTime;
        if (elapsed > timeoutSeconds * 1000) {
            activeSessions.remove(sessionId);
            return false;
        }
        
        return true;
    }
    
    public void closeSession(String sessionId) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            long duration = System.currentTimeMillis() - session.startTime;
            session.duration = duration / 1000; // en secondes
        }
    }
    
    static class SessionInfo {
        String userId;
        String sessionId;
        long startTime;
        long duration;
        
        SessionInfo(String userId, String sessionId, long startTime) {
            this.userId = userId;
            this.sessionId = sessionId;
            this.startTime = startTime;
            this.duration = 0;
        }
    }
}

/**
 * Logger pour la traçabilité des accès
 */
class AccessLogger {
    
    private List<LogEntry> logs;
    private SimpleDateFormat dateFormat;
    
    public AccessLogger() {
        this.logs = new ArrayList<>();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    }
    
    public void logEvent(String userId, String eventType, String details) {
        LogEntry entry = new LogEntry(
            userId,
            eventType,
            details,
            new Date()
        );
        logs.add(entry);
        
        // Écrire aussi dans un fichier
        saveToFile(entry);
    }
    
    public void displayLogs() {
        if (logs.isEmpty()) {
            System.out.println("Aucun log disponible");
            return;
        }
        
        System.out.println(String.format("%-20s %-20s %-15s %-30s",
            "Date/Heure", "Utilisateur", "Type", "Détails"));
        System.out.println("-".repeat(90));
        
        for (LogEntry log : logs) {
            System.out.println(String.format("%-20s %-20s %-15s %-30s",
                dateFormat.format(log.timestamp),
                log.userId,
                log.eventType,
                log.details));
        }
    }
    
    private void saveToFile(LogEntry entry) {
        try (FileWriter fw = new FileWriter("access_logs.txt", true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            
            out.println(String.format("%s | %s | %s | %s",
                dateFormat.format(entry.timestamp),
                entry.userId,
                entry.eventType,
                entry.details));
                
        } catch (IOException e) {
            System.err.println("Erreur lors de l'écriture du log: " + e.getMessage());
        }
    }
    
    static class LogEntry {
        String userId;
        String eventType;
        String details;
        Date timestamp;
        
        LogEntry(String userId, String eventType, String details, Date timestamp) {
            this.userId = userId;
            this.eventType = eventType;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
