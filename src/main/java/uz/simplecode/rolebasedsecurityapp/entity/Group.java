package uz.simplecode.rolebasedsecurityapp.entity;

import lombok.*;

import org.hibernate.annotations.*;
import org.hibernate.annotations.Parameter;

import javax.persistence.*;
import javax.persistence.Entity;
import java.util.UUID;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@Entity(name = "GROUPS")
public class Group {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(
            name = "UUID",
            strategy = "org.hibernate.id.UUIDGenerator",
            parameters = {
                    @Parameter(
                            name = "uuid_gen_strategy_class",
                            value = "org.hibernate.id.uuid.CustomVersionOneStrategy"
                    )}
    )
    @Column(name = "ID", nullable = false, updatable = false)
    private UUID id;
    @Column(name = "GROUP_NAME",nullable = false,unique = true)
    private String groupName;

    public Group(String groupName) {
        this.groupName = groupName;
    }
}
