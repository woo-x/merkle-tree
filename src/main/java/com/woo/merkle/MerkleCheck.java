package com.woo.merkle;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;
import com.woo.merkle.proto.MerkleBalanceVector;
import com.woo.merkle.proto.MerkleNode;
import com.woo.merkle.proto.MerkleTree;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.util.*;

public class MerkleCheck {


    public static void main(String args[]) throws Exception {
        MerkleCheck.check();
    }


    public static void check() throws Exception {


        String path = "path/to/your/binary/merkle/tree/file"; // the path of merkle tree binary file
        String userHash = "userhash of your account"; // the user hash of your woox account


        File file = new File(path);
        byte[] bytes = FileUtils.readFileToByteArray(file);

        Pair<List<String>, Map<ByteString, MerkleNode>> pair = deserializeData(bytes);
        List<String> tokens = pair.getKey();
        Map<ByteString, MerkleNode> nodeMap = pair.getRight();

        List<MerkleNode> userLeaves = doGetUserLeaves(nodeMap, userHash);
        Map<String, BigDecimal> balance = sumUserBalance(tokens, userLeaves);
        Set<ByteString> pathSet = doGetPathSet(userLeaves, pair.getRight());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        boolean ok = validateTree(nodeMap, digest, tokens, pathSet);

        for (String k : balance.keySet()) {
            System.out.println("you balance in audit " + k + " => " + balance.get(k));
        }
        System.out.println("validate result " + ok);




    }

    public static MerkleNode[] doGetLeaves(Map<ByteString, MerkleNode> map) {
        List<MerkleNode> leaves = new ArrayList<>();
        for (MerkleNode node : map.values()) {
            if (node.getLeft().size() == 0 && node.getRight().size() == 0) {
                leaves.add(node);
            }
        }
        MerkleNode[] array = new MerkleNode[leaves.size()];
        for (MerkleNode node : leaves) {
            array[node.getBalance().getLeafIdnex()] = node;
        }

        return array;
    }


    public static List<MerkleNode> doGetUserLeaves(Map<ByteString, MerkleNode> map, String userHash) throws Exception {

        MerkleNode[] array = doGetLeaves(map);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] userHashByte = Hex.decodeHex(userHash);
        List<MerkleNode> userLeaves = new ArrayList<>();
        for (int i = 0; i < array.length; i++) {
            ByteString hashInProto = array[i].getHash();
            MerkleBalanceVector merkleBalanceVector = array[i].getBalance();
            byte[] userProvidedHash = digest.digest(Bytes.concat(userHashByte, merkleBalanceVector.toByteArray()));
            if (Arrays.equals(hashInProto.toByteArray(), userProvidedHash)) {
                userLeaves.add(array[i]);
            }
        }

        return userLeaves;

    }


    public static Pair<List<String>, Map<ByteString, MerkleNode>> deserializeData(byte[] data) throws Exception {
        MerkleTree tree = MerkleTree.parseFrom(data);
        List<String> tokens = new ArrayList<>(tree.getTokensCount());
        for (int i = 0; i < tree.getTokensCount(); i++) {
            tokens.add(tree.getTokens(i));
        }
        Map<ByteString, MerkleNode> map = new HashMap<>();
        for (int i = 0; i < tree.getNodesCount(); i++) {
            MerkleNode node = tree.getNodes(i);
            map.put(node.getHash(), node);
        }
        return Pair.of(tokens, map);
    }

    public static Map<String, BigDecimal> sumUserBalance(List<String> tokens, List<MerkleNode> userLeaves) {
        Map<String, BigDecimal> balance = new HashMap<>();
        for (MerkleNode merkleNode : userLeaves) {
            MerkleBalanceVector merkleBalanceVector = merkleNode.getBalance();
            int size = merkleBalanceVector.getIndexCount();
            for (int i = 0; i < size; i++) {
                int tokenIndex = merkleBalanceVector.getIndex(i);
                String valStr = merkleBalanceVector.getBalances(i);
                String token = tokens.get(tokenIndex);
                BigDecimal val = new BigDecimal(valStr);
                BigDecimal cur = balance.getOrDefault(token, BigDecimal.ZERO);
                cur = cur.add(val);
                balance.put(token, cur);
            }
        }

        return balance;
    }

    private static Set<ByteString> doGetPathSet(List<MerkleNode> userLeaves, Map<ByteString, MerkleNode> nodeMap) {
        Set<ByteString> validationWaitingSet = new HashSet<>();
        LinkedList<MerkleNode> queue = new LinkedList<>();
        for (MerkleNode node : userLeaves) {
            queue.offer(node);
        }
        while (!queue.isEmpty()) {
            MerkleNode node = queue.poll();
            MerkleNode parent = nodeMap.get(node.getParent());
            if (parent != null && !validationWaitingSet.contains(parent.getHash())) {
                queue.offer(parent);
                validationWaitingSet.add(parent.getHash());
            }
        }
        return validationWaitingSet;
    }

    private static MerkleNode findRoot(Map<ByteString, MerkleNode> nodeMap) {
        MerkleNode root = null;
        for (MerkleNode node : nodeMap.values()) {
            if (node.getParent().size() == 0) {
                root = node;
                break;
            }
        }
        return root;
    }



    public static boolean validateTree(Map<ByteString, MerkleNode> nodeMap, MessageDigest digest, List<String> tokens, Set<ByteString> validationWaitingSet) {
        MerkleNode root = findRoot(nodeMap);
        return validateTree(root, nodeMap, digest, tokens, validationWaitingSet) != null;
    }

    private static Map<String, BigDecimal> validateChild(ByteString child, Map<ByteString, MerkleNode> nodeMap, MessageDigest digest, List<String> tokens, Set<ByteString> validationWaitingSet) {
        MerkleNode node = nodeMap.get(child);
        if (node == null) {
            throw new RuntimeException("child not found: " + child);
        }
        Map<String, BigDecimal> balance = validateTree(node, nodeMap, digest, tokens, validationWaitingSet);
        return balance;
    }

    private static Map<String, BigDecimal> validateTree(MerkleNode root, Map<ByteString, MerkleNode> nodeMap, MessageDigest digest, List<String> tokens, Set<ByteString> validationWaitingSet) {
        if (!validationWaitingSet.contains(root.getHash())) {
            return buildBalanceFromNode(root, tokens);
        }
        Map<String, BigDecimal> leftBalance = new HashMap<>();
        if (root.getLeft().size() != 0) {
            leftBalance = validateChild(root.getLeft(), nodeMap, digest, tokens, validationWaitingSet);
            if (leftBalance == null) {
                return null;
            }
        }
        Map<String, BigDecimal> rightBalance = new HashMap<>();
        if (root.getRight().size() != 0) {
            rightBalance = validateChild(root.getRight(), nodeMap, digest, tokens, validationWaitingSet);
            if (rightBalance == null) {
                return null;
            }
        }

        if (root.getLeft().size() == 0 && root.getRight().size() == 0) {
            // assuming the leaves are correct
//            throw new RuntimeException("impossible");
            return buildBalanceFromNode(root, tokens);
        } else {
            return validateIntermediateNode(root, leftBalance, rightBalance, digest, tokens);
        }

    }


    private static Map<String, BigDecimal> validateIntermediateNode(MerkleNode root, Map<String, BigDecimal> leftBalance, Map<String, BigDecimal> rightBalance, MessageDigest digest, List<String> tokens) {
        byte[] concatedHash = digest.digest(Bytes.concat(root.getLeft().toByteArray(), root.getRight().toByteArray()));
        if (!Arrays.equals(concatedHash, root.getHash().toByteArray())) {
            return null;
        }

        Map<String, BigDecimal> res = mergeBalance(leftBalance, rightBalance);
        Map<String, BigDecimal> nodeBalance = buildBalanceFromNode(root, tokens);
        if (!res.equals(nodeBalance)) {
            return null;
        }

        return nodeBalance;
    }

    private static Map<String, BigDecimal> mergeBalance(Map<String, BigDecimal> lhs, Map<String, BigDecimal> rhs) {
        Map<String, BigDecimal> res = new HashMap<>();
        Set<String> keys = new HashSet<>(lhs.keySet());
        keys.addAll(rhs.keySet());
        for (String k : keys) {
            BigDecimal lval = lhs.getOrDefault(k, BigDecimal.ZERO);
            BigDecimal rval = rhs.getOrDefault(k, BigDecimal.ZERO);
            res.put(k, lval.add(rval));
        }
        return res;
    }

    private static Map<String, BigDecimal> buildBalanceFromNode(MerkleNode node, List<String> tokens) {
        int count = node.getBalance().getBalancesCount();
        Map<String ,BigDecimal> res = new HashMap<>();
        for (int i = 0; i < count; i++) {
            String k = tokens.get(node.getBalance().getIndex(i));
            BigDecimal v = new BigDecimal(node.getBalance().getBalances(i));
            res.put(k, v);
        }
        return res;
    }







}
