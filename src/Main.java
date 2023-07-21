import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    private static KGC kgc;
    private static final List<User> users = new ArrayList<>();
    private static User currentUser;
    private static List<Object[]> publicKeys = new ArrayList<>();
    private static final List<Object[]> cipherData = new ArrayList<>();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        kgc = new KGC(512);
        System.out.println("Welcome to the Signcryption App!");

        int option;
        do {
            System.out.println("\nSelect an option:");
            System.out.println("1. Create User");
            System.out.println("2. Perform Signcryption");
            System.out.println("3. Perform Unsigncryption");
            System.out.println("0. Exit");
            option = scanner.nextInt();

            switch (option) {
                case 1 -> createUser(scanner);
                case 2 -> performSigncryption(scanner);
                case 3 -> performUnsigncryption(scanner);
                case 0 -> System.out.println("Exiting Signcryption App. Goodbye!");
                default -> System.out.println("Invalid option. Please try again.");
            }
        } while (option != 0);
    }

    private static void createUser(Scanner scanner) {
        System.out.print("Enter the user's identity: ");
        String identity = scanner.next();
        User user = new User(kgc, identity);
        users.add(user);
        updatePublicKeys();
        System.out.println("User created successfully!");
    }

    private static void performSigncryption(Scanner scanner) {
        updateCurrentUser(scanner);
        if (currentUser == null) {
            System.out.println("Please create a user first before performing signcryption.");
            return;
        }

        System.out.print("Enter the message to signcrypt: ");
        String message = scanner.next();
        System.out.println("Enter the user identity to send data to : ");
        String userID = scanner.next();
        User user = findUserByIdentity(userID);
        if(user != null){
            user.setOrder(message.getBytes());
        }
        Object[] userCipherData = currentUser.signcrypt(message);
        cipherData.add(userCipherData);
        System.out.println("Signcryption successful!");
    }

    private static void performUnsigncryption(Scanner scanner) {
        updateCurrentUser(scanner);
        if (currentUser == null) {
            System.out.println("Please create a user first before performing unsigncryption.");
            return;
        }

        // Perform unsigncryption using KGC aggregate method
        Object[] aggregatedCipherText = kgc.aggregate(cipherData);
        Object[] recoveredData = currentUser.unsigncrypt(aggregatedCipherText, publicKeys);

        boolean isUnsigncryptionSuccessful = (boolean) recoveredData[0];
        byte[] recoveredMessage = (byte[]) recoveredData[1];

        if (isUnsigncryptionSuccessful) {
            System.out.println("Unsigncryption successful!");
            System.out.println("Recovered Message: " + new String(recoveredMessage));
        } else {
            System.out.println("Unsigncryption failed!.");
            System.out.println(new String(recoveredMessage));
        }
    }

    private static void updatePublicKeys() {
        publicKeys = new ArrayList<>();
        for (User user: users) {
            Object[] obj = {user.getIdentity(),user.getPartialPublicKey(),user.getPublicKey()};
            publicKeys.add(obj);
        }
    }

    private static void updateCurrentUser(Scanner scanner) {
        System.out.println("Enter your identity : ");
        String id = scanner.next();
        currentUser = findUserByIdentity(id);
    }

    private static User findUserByIdentity(String identity) {
        for (User user : users) {
            if (user.getIdentity().equals(identity)) {
                return user;
            }
        }
        return null;
    }
}
